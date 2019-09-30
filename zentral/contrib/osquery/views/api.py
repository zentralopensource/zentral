from base64 import b64decode
import logging
from django.core.exceptions import SuspiciousOperation
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import transaction
from django.db.models import Q
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.models import MachineSnapshot, MetaMachine
from zentral.contrib.inventory.utils import (commit_machine_snapshot_and_trigger_events,
                                             verify_enrollment_secret)
from zentral.core.events.base import post_machine_conflict_event
from zentral.core.probes.models import ProbeSource
from zentral.utils.api_views import JSONPostAPIView, verify_secret, APIAuthError
from zentral.contrib.inventory.conf import MACOS, platform_with_os_name
from zentral.contrib.osquery.conf import (build_osquery_conf,
                                          get_distributed_inventory_queries,
                                          INVENTORY_QUERY_NAME,
                                          INVENTORY_DISTRIBUTED_QUERY_PREFIX)
from zentral.contrib.osquery.events import (post_distributed_query_result, post_enrollment_event,
                                            post_file_carve_events,
                                            post_events_from_osquery_log, post_request_event)
from zentral.contrib.osquery.models import (CarveBlock, CarveSession,
                                            DistributedQueryProbeMachine,
                                            enroll, EnrolledMachine,
                                            SOURCE_MODULE)
from zentral.contrib.osquery.tasks import build_carve_session_archive
from .utils import update_tree_with_inventory_query_snapshot

logger = logging.getLogger('zentral.contrib.osquery.views.api')


class EnrollView(JSONPostAPIView):
    def get_enroll_secret(self, data):
        try:
            return data["enroll_secret"]
        except KeyError:
            raise SuspiciousOperation("Missing enroll_secret key in osquery enroll request")

    def get_serial_number(self, data):
        try:
            serial_number = data["host_details"]["system_info"]["hardware_serial"].strip()
        except (KeyError, AttributeError):
            serial_number = None
        if serial_number is None:
            # special configuration for linux machines. see install script.
            serial_number = data.get("host_identifier", None)
        if not serial_number:
            raise APIAuthError("No serial number")
        return serial_number

    def get_uuid(self, data):
        try:
            return data["host_details"]["system_info"]["uuid"].strip()
        except (KeyError, AttributeError):
            pass

    def verify_enrollment_secret(self, enroll_secret, serial_number, uuid):
        try:
            es_request = verify_enrollment_secret(
                "osquery_enrollment", enroll_secret,
                self.user_agent, self.ip,
                serial_number, uuid
            )
        except EnrollmentSecretVerificationFailed:
            raise APIAuthError("Unknown enrolled machine")
        else:
            self.enrollment = es_request.enrollment_secret.osquery_enrollment
            self.machine_serial_number = serial_number
            self.business_unit = self.enrollment.secret.get_api_enrollment_business_unit()

    def verify_signed_secret(self, enroll_secret):
        api_secret_data = verify_secret(enroll_secret, SOURCE_MODULE)
        self.machine_serial_number = api_secret_data.get('machine_serial_number', None)
        if not self.machine_serial_number:
            raise APIAuthError("No serial number")
        self.business_unit = api_secret_data.get("business_unit", None)

    def check_data_secret(self, data):
        enroll_secret = self.get_enroll_secret(data)
        self.enrollment = None
        if ":" not in enroll_secret:
            # new way, with Enrollment model
            serial_number = self.get_serial_number(data)
            uuid = self.get_uuid(data)
            self.verify_enrollment_secret(enroll_secret, serial_number, uuid)
        else:
            # old way, with a signed enroll_secret
            self.verify_signed_secret(enroll_secret)

    def do_post(self, data):
        machine_snapshot, action = enroll(self.enrollment,
                                          self.machine_serial_number,
                                          self.business_unit,
                                          data.get("host_identifier"),
                                          self.ip)
        if machine_snapshot and action:
            post_enrollment_event(machine_snapshot.serial_number,
                                  self.user_agent, self.ip,
                                  {'action': action})
            return {'node_key': machine_snapshot.reference}
        else:
            raise SuspiciousOperation("Could not enroll machine")


class BaseNodeView(JSONPostAPIView):
    enrollment = None
    machine_snapshot = None

    def get_enrolled_machine(self):
        try:
            return (EnrolledMachine.objects.select_related("enrollment__configuration",
                                                           "enrollment__secret__meta_business_unit")
                                           .get(node_key=self.node_key))
        except EnrolledMachine.DoesNotExist:
            pass

    def get_machine_snapshot(self):
        if not self.machine_snapshot:
            auth_err = None
            try:
                self.machine_snapshot = MachineSnapshot.objects.current().get(source__module=SOURCE_MODULE,
                                                                              reference=self.node_key)
            except MachineSnapshot.DoesNotExist:
                auth_err = "Wrong node_key"
            except MachineSnapshot.MultipleObjectsReturned:
                auth_err = "Multiple current osquery machine snapshots for node key '{}'".format(self.node_key)
            if auth_err:
                logger.error("APIAuthError %s", auth_err)
                raise APIAuthError(auth_err)
        return self.machine_snapshot

    def check_data_secret(self, data):
        # get the node_key
        try:
            self.node_key = data["node_key"]
        except KeyError:
            raise APIAuthError("Missing node_key in osquery request")

        enrolled_machine = self.get_enrolled_machine()
        if enrolled_machine:
            # new way
            self.enrollment = enrolled_machine.enrollment
            self.machine_serial_number = enrolled_machine.serial_number
            self.business_unit = self.enrollment.secret.get_api_enrollment_business_unit()
        if not enrolled_machine:
            # old way, look for a MachineSnapshot with the node_key as reference
            # TODO: deprecate and remove
            machine_snapshot = self.get_machine_snapshot()
            self.machine_serial_number = machine_snapshot.serial_number
            self.business_unit = machine_snapshot.business_unit

    def do_post(self, data):
        post_request_event(self.machine_serial_number,
                           self.user_agent, self.ip,
                           self.request_type,
                           self.enrollment)
        return self.do_node_post(data)

    def commit_inventory_query_result(self, snapshot):
        tree = self.get_machine_snapshot().serialize()
        tree["serial_number"] = self.machine_serial_number
        tree["public_ip_address"] = self.ip
        if self.business_unit:
            tree['business_unit'] = self.business_unit.serialize()

        update_tree_with_inventory_query_snapshot(tree, snapshot)

        commit_machine_snapshot_and_trigger_events(tree)


class ConfigView(BaseNodeView):
    request_type = "config"

    def do_node_post(self, data):
        return build_osquery_conf(MetaMachine(self.machine_serial_number), self.enrollment)


class CarverStartView(BaseNodeView):
    request_type = "carve_start"

    def do_node_post(self, data):
        probe_source_id = int(data["request_id"].split("_")[-1])
        probe_source = ProbeSource.objects.get(pk=probe_source_id)
        session_id = get_random_string(64)
        CarveSession.objects.create(probe_source=probe_source,
                                    machine_serial_number=self.machine_serial_number,
                                    session_id=session_id,
                                    carve_guid=data["carve_id"],
                                    carve_size=int(data["carve_size"]),
                                    block_size=int(data["block_size"]),
                                    block_count=int(data["block_count"]))
        post_file_carve_events(self.machine_serial_number, self.user_agent, self.ip,
                               [{"probe": {"id": probe_source.pk,
                                           "name": probe_source.name},
                                 "action": "start",
                                 "session_id": session_id}])
        return {"session_id": session_id}


class CarverContinueView(BaseNodeView):
    request_type = "carve_continue"

    def check_data_secret(self, data):
        # no node_key, use the session_id
        # TODO: better?
        auth_err = None
        try:
            self.session_id = data["session_id"]
            self.carve_session = CarveSession.objects.get(session_id=self.session_id)
            self.machine_serial_number = self.carve_session.machine_serial_number
        except KeyError:
            auth_err = "Missing session id"
        except CarveSession.DoesNotExist:
            auth_err = "Unknown session id"
        if auth_err:
            logger.error("APIAuthError %s", auth_err, extra=data)
            raise APIAuthError(auth_err)

    def do_node_post(self, data):
        data_data = data.pop("data")

        block_id = data["block_id"]
        cb = CarveBlock.objects.create(carve_session=self.carve_session,
                                       block_id=int(block_id))
        cb.file.save(str(block_id), SimpleUploadedFile(str(block_id), b64decode(data_data)))

        session_finished = (CarveBlock.objects.filter(carve_session=self.carve_session).count()
                            == self.carve_session.block_count)
        probe_source = self.carve_session.probe_source
        post_file_carve_events(self.machine_serial_number, self.user_agent, self.ip,
                               [{"probe": {"id": probe_source.pk,
                                           "name": probe_source.name},
                                 "action": "continue",
                                 "block_id": block_id,
                                 "block_size": len(data_data),
                                 "session_finished": session_finished,
                                 "session_id": self.session_id}])
        if session_finished:
            build_carve_session_archive.apply_async((self.session_id,))
        return {}


class DistributedReadView(BaseNodeView):
    request_type = "distributed_read"

    def do_node_post(self, data):
        queries = {}
        if self.machine_serial_number:
            machine = MetaMachine(self.machine_serial_number)
            queries = DistributedQueryProbeMachine.objects.new_queries_for_machine(machine)
            for query_name, query in get_distributed_inventory_queries(machine, self.get_machine_snapshot()):
                if query_name in queries:
                    logger.error("Conflict on the distributed query name %s", query_name)
                else:
                    queries[query_name] = query
        return {'queries': queries}


class DistributedWriteView(BaseNodeView):
    request_type = "distributed_write"

    @transaction.non_atomic_requests
    def do_node_post(self, data):
        dq_payloads = []
        fc_payloads = []

        def get_probe_pk(key):
            return int(key.split('_')[-1])

        queries = data['queries']

        ps_d = {ps.id: ps
                for ps in ProbeSource.objects.filter(
                    pk__in=[get_probe_pk(k) for k in queries.keys()
                            if not k.startswith(INVENTORY_DISTRIBUTED_QUERY_PREFIX)]
                ).filter(
                    Q(model='OsqueryDistributedQueryProbe') | Q(model='OsqueryFileCarveProbe')
                )}
        inventory_snapshot = []
        for key, val in queries.items():
            try:
                status = int(data['statuses'][key])
            except KeyError:
                # osquery < 2.1.2 has no statuses
                status = 0
            if key.startswith(INVENTORY_DISTRIBUTED_QUERY_PREFIX):
                if status == 0 and val:
                    inventory_snapshot.extend(val)
                else:
                    logger.warning("Inventory distributed query write with status = %s and val = %s",
                                   status, val)
            else:
                try:
                    probe_source = ps_d[get_probe_pk(key)]
                except KeyError:
                    logger.error("Unknown distributed query probe %s", key)
                else:
                    payload = {'probe': {'id': probe_source.pk,
                                         'name': probe_source.name}}
                    if status > 0:
                        # error
                        payload["error"] = True
                        payload["empty"] = True
                    elif status == 0:
                        payload["error"] = False
                        if val:
                            payload["result"] = val
                            payload["empty"] = False
                        else:
                            payload["empty"] = True
                    else:
                        raise ValueError("Unknown distributed query status '{}'".format(status))
                    if probe_source.model == 'OsqueryDistributedQueryProbe':
                        dq_payloads.append(payload)
                    else:
                        fc_payloads.append(payload)
            if dq_payloads:
                post_distributed_query_result(self.machine_serial_number,
                                              self.user_agent, self.ip,
                                              dq_payloads)
            if fc_payloads:
                post_file_carve_events(self.machine_serial_number,
                                       self.user_agent, self.ip,
                                       fc_payloads)
        if inventory_snapshot:
            self.commit_inventory_query_result(inventory_snapshot)
        return {}


class LogView(BaseNodeView):
    request_type = "log"

    def check_data_secret(self, data):
        super().check_data_secret(data)
        self.data_data = data.pop("data")
        for r in self.data_data:
            decorations = r.pop("decorations", None)
            if decorations:
                platform = platform_with_os_name(decorations.get("os_name"))
                if platform == MACOS:
                    hardware_serial = decorations.get("hardware_serial")
                    if hardware_serial and hardware_serial != self.machine_serial_number:
                        # The SN reported by osquery is not the one configured in the enrollment secret.
                        # For other platforms than MACOS, it could happen. For example, we take the GCE instance ID as
                        # serial number in the enrollment secret for linux, if possible.
                        # Osquery builds one from the SMBIOS/DMI.
                        auth_err = "osquery reported SN {} different from enrollment SN {}".format(
                            hardware_serial,
                            self.machine_serial_number
                        )
                        post_machine_conflict_event(self.request, SOURCE_MODULE,
                                                    hardware_serial, self.machine_serial_number,
                                                    decorations)
                        raise APIAuthError(auth_err)

    @transaction.non_atomic_requests
    def do_node_post(self, data):
        inventory_results = []
        other_results = []
        for r in self.data_data:
            if r.get('name', None) == INVENTORY_QUERY_NAME:
                inventory_results.append((r['unixTime'], r['snapshot']))
            else:
                other_results.append(r)
        if inventory_results:
            inventory_results.sort(reverse=True)
            last_snapshot = inventory_results[0][1]
            self.commit_inventory_query_result(last_snapshot)
        data['data'] = other_results
        post_events_from_osquery_log(self.machine_serial_number,
                                     self.user_agent, self.ip, data)
        return {}

from base64 import b64decode
from datetime import datetime
from gzip import GzipFile
from itertools import chain, islice
import json
import logging
from django.core.exceptions import SuspiciousOperation, PermissionDenied
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import transaction
from django.http import Http404, JsonResponse
from django.utils.crypto import get_random_string
from django.views.generic import View
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.models import MachineSnapshot, MetaMachine, MachineTag
from zentral.contrib.inventory.utils import (commit_machine_snapshot_and_trigger_events,
                                             verify_enrollment_secret)
from zentral.contrib.osquery.compliance_checks import ComplianceCheckStatusAggregator
from zentral.contrib.osquery.conf import build_osquery_conf, INVENTORY_QUERY_NAME
from zentral.contrib.osquery.events import (post_enrollment_event,
                                            post_file_carve_events,
                                            post_request_event, post_results, post_status_logs)
from zentral.contrib.osquery.models import (parse_result_name,
                                            DistributedQuery, DistributedQueryMachine, DistributedQueryResult,
                                            EnrolledMachine,
                                            FileCarvingBlock, FileCarvingSession,
                                            PackQuery)
from zentral.contrib.osquery.tasks import build_file_carving_session_archive
from zentral.core.events.base import post_machine_conflict_event
from zentral.utils.http import user_agent_and_ip_address_from_request
from zentral.utils.json import remove_null_character
from .views.utils import (prepare_file_carving_session_if_necessary,
                          update_tree_with_enrollment_host_details, update_tree_with_inventory_query_snapshot)


logger = logging.getLogger('zentral.contrib.osquery.views.api')


class NodeInvalidError(Exception):
    pass


class BaseJsonPostView(View):
    def authenticate(self):
        pass

    def post(self, request, *args, **kwargs):
        try:
            if request.META.get("HTTP_CONTENT_ENCODING") == "gzip":
                self.data = json.load(GzipFile(fileobj=request))
            else:
                self.data = json.loads(request.body)
        except ValueError:
            raise SuspiciousOperation("Could not read JSON data")
        self.user_agent, self.ip = user_agent_and_ip_address_from_request(request)
        try:
            self.authenticate()
            return JsonResponse(self.do_post())
        except NodeInvalidError:
            return JsonResponse({"node_invalid": True})


class EnrollView(BaseJsonPostView):
    def get_enroll_secret(self):
        enroll_secret = self.data.get("enroll_secret")
        if not enroll_secret:
            raise SuspiciousOperation("Missing 'enroll_secret' key")
        return enroll_secret

    def get_serial_number(self):
        try:
            serial_number = self.data["host_details"]["system_info"]["hardware_serial"].strip()
        except (KeyError, AttributeError):
            serial_number = None
        if not serial_number:
            # special configuration for linux machines. see install script.
            serial_number = self.data.get("host_identifier")
        if not serial_number:
            raise SuspiciousOperation("Missing serial number")
        return serial_number

    def get_uuid(self):
        try:
            return self.data["host_details"]["system_info"]["uuid"].strip()
        except (KeyError, AttributeError):
            pass

    def authenticate(self):
        self.serial_number = self.get_serial_number()
        try:
            self.es_request = verify_enrollment_secret(
                "osquery_enrollment",
                self.get_enroll_secret(),
                self.user_agent, self.ip,
                self.serial_number,
                self.get_uuid()
            )
        except EnrollmentSecretVerificationFailed:
            logger.error("Machine %s: wrong enrollment secret", self.serial_number, extra={'request': self.request})
            raise NodeInvalidError

    def do_post(self):
        enrollment = self.es_request.enrollment_secret.osquery_enrollment

        # update or create enrolled machine
        enrolled_machine_defaults = {"node_key": get_random_string(32)}
        try:
            enrolled_machine_defaults["platform_mask"] = int(self.data["platform_type"])
        except (KeyError, ValueError, TypeError):
            logger.error("Could not get platform_mask from enrollment data")
        try:
            enrolled_machine_defaults["osquery_version"] = self.data["host_details"]["osquery_info"]["version"]
        except KeyError:
            logger.error("Could not get osquery version from enrollment data")
        enrolled_machine, enrolled_machine_created = EnrolledMachine.objects.update_or_create(
            enrollment=enrollment,
            serial_number=self.serial_number,
            defaults=enrolled_machine_defaults
        )

        # apply enrollment secret tags
        for tag in enrollment.secret.tags.all():
            MachineTag.objects.get_or_create(serial_number=self.serial_number, tag=tag)

        # delete other enrolled machines
        deleted_enrolled_machines, _ = (EnrolledMachine.objects.exclude(pk=enrolled_machine.pk)
                                                               .filter(serial_number=self.serial_number)
                                                               .delete())
        if deleted_enrolled_machines or not enrolled_machine_created:
            enrollment_action = 're-enrollment'
        else:
            enrollment_action = 'enrollment'

        # create machine snapshot if necessary
        if not MachineSnapshot.objects.filter(source__module="zentral.contrib.osquery",
                                              source__name="osquery",
                                              serial_number=self.serial_number,
                                              reference=enrolled_machine.node_key).exists():
            tree = {"source": {"module": "zentral.contrib.osquery",
                               "name": "osquery"},
                    "serial_number": self.serial_number,
                    "reference": enrolled_machine.node_key,
                    "public_ip_address": self.ip}
            business_unit = enrollment.secret.get_api_enrollment_business_unit()
            if business_unit:
                tree["business_unit"] = business_unit.serialize()
            update_tree_with_enrollment_host_details(tree, self.data.get("host_details"))
            commit_machine_snapshot_and_trigger_events(tree)

        post_enrollment_event(self.serial_number,
                              self.user_agent, self.ip,
                              {'action': enrollment_action})

        return {'node_key': enrolled_machine.node_key}


class BaseNodeView(BaseJsonPostView):
    request_type = None

    def get_node_key(self):
        node_key = self.data.get("node_key")
        if not node_key:
            raise SuspiciousOperation("Missing node_key")
        return node_key

    def authenticate(self):
        try:
            self.enrolled_machine = EnrolledMachine.objects.select_related(
                "enrollment__configuration",
                "enrollment__secret__meta_business_unit"
            ).get(node_key=self.get_node_key())
        except EnrolledMachine.DoesNotExist:
            logger.error("Wrong node_key", extra={'request': self.request})
            raise NodeInvalidError
        self.machine = MetaMachine(self.enrolled_machine.serial_number)
        self.enrollment = self.enrolled_machine.enrollment

    def do_post(self):
        post_request_event(self.machine.serial_number,
                           self.user_agent, self.ip,
                           self.request_type,
                           self.enrollment)
        return self.do_node_post()


class ConfigView(BaseNodeView):
    request_type = "config"

    def do_node_post(self):
        return build_osquery_conf(self.machine, self.enrollment)


class StartFileCarvingView(BaseNodeView):
    request_type = "start_file_carving"

    def do_node_post(self):
        carve_guid = self.data.get("carve_id")
        if not carve_guid:
            raise SuspiciousOperation("Missing carve_id")

        try:
            fcs = FileCarvingSession.objects.get(carve_guid=carve_guid)
        except FileCarvingSession.DoesNotExist:
            raise Http404("Unknown carve_id")

        if fcs.filecarvingblock_set.count():
            raise SuspiciousOperation("File carving session already has blocks")

        fcs_updated = False
        for attr in ("block_count", "block_size", "carve_size"):
            val = self.data.get(attr)
            if getattr(fcs, attr) == -1:
                fcs_updated = True
                setattr(fcs, attr, val)
        if fcs_updated:
            fcs.save()
        else:
            logger.error("File carving session %s not updated", fcs.pk, extra={'request': self.request})

        session_id = str(fcs.pk)
        post_file_carve_events(self.machine.serial_number, self.user_agent, self.ip,
                               [{"action": "start",
                                 "session_id": session_id}])
        return {"session_id": session_id}


class ContinueFileCarvingView(BaseNodeView):
    request_type = "continue_file_carving"

    def authenticate(self):
        try:
            session_id = self.data["session_id"]
        except KeyError:
            raise SuspiciousOperation("Missing session_id")
        try:
            self.session = FileCarvingSession.objects.select_for_update().get(pk=session_id)
        except FileCarvingSession.DoesNotExist:
            raise PermissionDenied("Unknown session_id")
        # TODO: better. "There can be only one"
        try:
            self.enrolled_machine = (
                EnrolledMachine.objects.select_related("enrollment__configuration")
                                       .filter(serial_number=self.session.serial_number)
                                       .order_by("-pk")[0]
            )
        except IndexError:
            raise PermissionDenied("Unknown machine")
        self.machine = MetaMachine(self.session.serial_number)
        self.enrollment = self.enrolled_machine.enrollment

    def do_node_post(self):
        try:
            block_id = int(self.data["block_id"])
        except KeyError:
            raise SuspiciousOperation("Missing block_id")
        except ValueError:
            raise SuspiciousOperation("Invalid block_id")
        else:
            block_filename = str(block_id)
        try:
            block_data = b64decode(self.data["data"])
        except KeyError:
            raise SuspiciousOperation("Missing block data")
        except Exception:
            raise SuspiciousOperation("Could not read block data")

        cb = FileCarvingBlock.objects.create(file_carving_session=self.session, block_id=block_id)
        cb.file.save(block_filename, SimpleUploadedFile(block_filename, block_data))

        session_finished = (FileCarvingBlock.objects.filter(file_carving_session=self.session).count()
                            == self.session.block_count)
        post_file_carve_events(self.machine.serial_number, self.user_agent, self.ip,
                               [{"action": "continue",
                                 "block_id": block_id,
                                 "session_finished": session_finished,
                                 "session_id": str(self.session.pk)}])
        if session_finished:
            transaction.on_commit(lambda: build_file_carving_session_archive.apply_async((str(self.session.pk),)))
        return {}


class DistributedReadView(BaseNodeView):
    request_type = "distributed_read"
    batch_size = 10  # TODO: hard coded

    def do_node_post(self):
        dqm_list = []
        for distributed_query in islice(
            DistributedQuery.objects.iter_queries_for_enrolled_machine(self.enrolled_machine, self.machine.tags),
            self.batch_size
        ):
            dqm_list.append(
                DistributedQueryMachine(
                    distributed_query=distributed_query,
                    serial_number=self.machine.serial_number
                )
            )
        queries = {}
        if dqm_list:
            DistributedQueryMachine.objects.bulk_create(dqm_list)
            for dqm in dqm_list:
                queries[str(dqm.pk)] = dqm.distributed_query.sql
        return {'queries': queries}


class DistributedWriteView(BaseNodeView):
    request_type = "distributed_write"
    batch_size = 100  # TODO hard coded

    def do_node_post(self):
        results = self.data.get("queries", {})
        statuses = self.data.get("statuses", {})
        messages = self.data.get("messages", {})
        stats = self.data.get("stats", {})
        dqm_pk_set = set(chain(results.keys(), statuses.keys(), messages.keys(), stats.keys()))
        if not dqm_pk_set:
            return {}
        dqm_cache = {str(dqm.pk): dqm
                     for dqm in DistributedQueryMachine.objects
                                                       .select_related("distributed_query__query__compliance_check")
                                                       .filter(pk__in=dqm_pk_set)}

        # update distributed query machines
        for dqm_pk, dqm in dqm_cache.items():
            # status
            dqm_status = statuses.get(dqm_pk)
            if dqm_status is None:
                logger.warning("Missing status for DistributedQueryMachine %s", dqm_pk)
                dqm_status = 999  # TODO: better?
            dqm.status = dqm_status
            # error message
            dqm.error_message = messages.get(dqm_pk)
            # stats
            dqm_stats = stats.get(dqm_pk)
            if dqm_stats:
                for stat_attr in ("memory", "system_time", "user_time", "wall_time_ms"):
                    val = dqm_stats.get(stat_attr)
                    if val is not None:
                        try:
                            val = int(val)
                        except (TypeError, ValueError):
                            pass
                        else:
                            setattr(dqm, stat_attr, val)
            dqm.save()

        # save_results
        dq_results = (
            DistributedQueryResult(
                distributed_query=dqm.distributed_query,
                serial_number=self.machine.serial_number,
                row=remove_null_character(row)
            )
            for dqm_pk, dqm in dqm_cache.items()
            for row in results.get(dqm_pk, [])
        )
        while True:
            batch = list(islice(dq_results, self.batch_size))
            if not batch:
                break
            DistributedQueryResult.objects.bulk_create(batch, self.batch_size)

        # process file carving
        for dqm_pk, dqm_results in results.items():
            for columns in dqm_results:
                file_carving_session = prepare_file_carving_session_if_necessary(columns)
                if file_carving_session:
                    file_carving_session.serial_number = self.machine.serial_number
                    file_carving_session.distributed_query = dqm_cache[dqm_pk].distributed_query
                    file_carving_session.save()
                    post_file_carve_events(self.machine.serial_number, self.user_agent, self.ip,
                                           [{"action": "schedule",
                                             "session_id": str(file_carving_session.pk)}])
                # only test the first tuple
                break

        # process compliance checks
        cc_status_agg = ComplianceCheckStatusAggregator(self.machine.serial_number)
        status_time = datetime.utcnow()  # TODO: how to get a better time? add ztl_status_time = now() to the query?
        for dqm_pk, dqm in dqm_cache.items():
            distributed_query = dqm.distributed_query
            query = distributed_query.query
            if not query or not query.compliance_check:
                continue
            cc_status_agg.add_result(
                query.pk,
                distributed_query.query_version,
                status_time,
                results.get(dqm_pk, []),
                distributed_query.pk
            )
        cc_status_agg.commit_and_post_events()

        return {}


class LogView(BaseNodeView):
    request_type = "log"

    def process_decorations(self, records):
        if not records:
            return
        decorations = records[-1].get("decorations", {})

        # verify serial number
        serial_number = decorations.get("serial_number")
        if serial_number and serial_number != self.machine.serial_number:
            logger.warning(
                "osquery reported SN %s different from enrolled machine SN %s",
                serial_number, self.machine.serial_number
            )
            post_machine_conflict_event(self.request, "zentral.contrib.osquery",
                                        serial_number, self.machine.serial_number,
                                        decorations)
            raise NodeInvalidError

        # update osquery version if necessary
        osquery_version = decorations.get("version")
        if osquery_version and self.enrolled_machine.osquery_version != osquery_version:
            self.enrolled_machine.osquery_version = osquery_version
            self.enrolled_machine.save()

    @transaction.non_atomic_requests
    def do_node_post(self):
        records = self.data.pop("data", [])
        if not records:
            logger.warning("No records found")
            return {}

        records.sort(key=lambda r: r.get("unixTime", 0))
        self.process_decorations(records)

        log_type = self.data.get("log_type")
        if log_type == "result":
            results = []
            last_inventory_snapshot = None
            for record in records:
                if record.get("name") == INVENTORY_QUERY_NAME:
                    last_inventory_snapshot = record.get("snapshot")
                else:
                    results.append(record)
                    # file carving ?
                    columns = None
                    if "columns" in record:
                        columns = record["columns"]
                    elif "snapshot" in record:
                        try:
                            columns = record["snapshot"][0]
                        except IndexError:
                            pass
                    if columns:
                        file_carving_session = prepare_file_carving_session_if_necessary(columns)
                        if file_carving_session:
                            try:
                                pack_pk, query_pk, _, _ = parse_result_name(record["name"])
                                pack_query = PackQuery.objects.get(pack__pk=pack_pk, query__pk=query_pk)
                            except Exception:
                                logger.exception("could not find file carving result pack query")
                            else:
                                file_carving_session.serial_number = self.machine.serial_number
                                file_carving_session.pack_query = pack_query
                                file_carving_session.save()
                                post_file_carve_events(self.machine.serial_number, self.user_agent, self.ip,
                                                       [{"action": "schedule",
                                                         "session_id": str(file_carving_session.pk)}])
            if last_inventory_snapshot:
                tree = {"source": {"module": "zentral.contrib.osquery",
                                   "name": "osquery"},
                        "serial_number": self.machine.serial_number,
                        "reference": self.enrolled_machine.node_key,
                        "public_ip_address": self.ip}
                business_unit = self.enrollment.secret.get_api_enrollment_business_unit()
                if business_unit:
                    tree["business_unit"] = business_unit.serialize()
                update_tree_with_inventory_query_snapshot(tree, last_inventory_snapshot)
                commit_machine_snapshot_and_trigger_events(tree)
            post_results(self.machine.serial_number, self.user_agent, self.ip, results)
        elif log_type == "status":
            # TODO: configuration option to filter some of those (severity) or maybe simply ignore them
            post_status_logs(self.machine.serial_number, self.user_agent, self.ip, records)
        else:
            logger.error("Unknown log type %s", log_type)

        return {}

import json
import logging
from django.core.exceptions import SuspiciousOperation
from django.db import transaction
from zentral.contrib.inventory.models import MachineSnapshot, MetaMachine
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_trigger_events
from zentral.core.probes.models import ProbeSource
from zentral.utils.api_views import JSONPostAPIView, verify_secret, APIAuthError
from zentral.contrib.osquery.conf import (build_osquery_conf,
                                          get_distributed_inventory_queries,
                                          INVENTORY_QUERY_NAME,
                                          INVENTORY_DISTRIBUTED_QUERY_PREFIX)
from zentral.contrib.osquery.events import (post_distributed_query_result, post_enrollment_event,
                                            post_events_from_osquery_log, post_request_event)
from zentral.contrib.osquery.models import enroll, DistributedQueryProbeMachine

logger = logging.getLogger('zentral.contrib.osquery.views.api')


class EnrollView(JSONPostAPIView):
    def check_data_secret(self, data):
        try:
            data = verify_secret(data['enroll_secret'], "zentral.contrib.osquery")
        except KeyError:
            raise SuspiciousOperation("Osquery enroll request without enroll secret")
        try:
            self.machine_serial_number = data['machine_serial_number']
        except KeyError:
            raise SuspiciousOperation("Osquery enroll secret without machine serial number")
        self.business_unit = data.get('business_unit', None)

    def do_post(self, data):
        ms, action = enroll(self.machine_serial_number,
                            self.business_unit,
                            data.get("host_identifier"),
                            self.ip)
        if ms and action:
            post_enrollment_event(ms.serial_number,
                                  self.user_agent, self.ip,
                                  {'action': action})
            return {'node_key': ms.reference}
        else:
            raise RuntimeError("Could not enroll client")


class BaseNodeView(JSONPostAPIView):
    def check_data_secret(self, data):
        auth_err = None
        try:
            self.ms = MachineSnapshot.objects.current().get(source__module='zentral.contrib.osquery',
                                                            reference=data['node_key'])
        except KeyError:
            auth_err = "Missing node_key"
        except MachineSnapshot.DoesNotExist:
            auth_err = "Wrong node_key"
        except MachineSnapshot.MultipleObjectsReturned:
            auth_err = "Multiple current osquery machine snapshots for node key '{}'".format(data['node_key'])
        if auth_err:
            logger.error("APIAuthError %s", auth_err, extra=data)
            raise APIAuthError(auth_err)
        # TODO: Better verification ?
        self.machine_serial_number = self.ms.serial_number
        self.business_unit = self.ms.business_unit

    def do_post(self, data):
        post_request_event(self.machine_serial_number,
                           self.user_agent, self.ip,
                           self.request_type)
        return self.do_node_post(data)

    def commit_inventory_query_result(self, snapshot):
        tree = self.ms.serialize()
        tree["serial_number"] = self.machine_serial_number
        tree["public_ip_address"] = self.ip
        if self.business_unit:
            tree['business_unit'] = self.business_unit.serialize()

        def clean_dict(d):
            for k, v in list(d.items()):
                if v is None or v == "":
                    del d[k]
            return d

        deb_packages = []
        network_interfaces = []
        osx_app_instances = []
        for t in snapshot:
            table_name = t.pop('table_name')
            if table_name == 'os_version':
                os_version = clean_dict(t)
                if os_version:
                    tree['os_version'] = os_version
            elif table_name == 'system_info':
                system_info = clean_dict(t)
                if system_info:
                    tree['system_info'] = system_info
            if table_name == 'deb_packages':
                deb_package = clean_dict(t)
                if deb_package:
                    if deb_package not in deb_packages:
                        deb_packages.append(deb_package)
                    else:
                        logger.warning("Duplicated deb package")
            elif table_name == 'network_interface':
                network_interface = clean_dict(t)
                if network_interface:
                    if network_interface not in network_interfaces:
                        network_interfaces.append(network_interface)
                    else:
                        logger.warning("Duplicated network interface")
            elif table_name == 'apps':
                bundle_path = t.pop('bundle_path')
                osx_app = clean_dict(t)
                if osx_app and bundle_path:
                    osx_app_instance = {'app': osx_app,
                                        'bundle_path': bundle_path}
                    if osx_app_instance not in osx_app_instances:
                        osx_app_instances.append(osx_app_instance)
                    else:
                        logger.warning("Duplicated osx app instance")
        if deb_packages:
            tree["deb_packages"] = deb_packages
        if network_interfaces:
            tree["network_interfaces"] = network_interfaces
        if osx_app_instances:
            tree["osx_app_instances"] = osx_app_instances
        commit_machine_snapshot_and_trigger_events(tree)


class ConfigView(BaseNodeView):
    request_type = "config"

    def do_node_post(self, data):
        # TODO: The machine serial number is included in the string used to authenticate the requests
        # This is done in the osx pkg builder. The machine serial number should always be present here.
        # Maybe we could code a fallback to the available mbu probes if the serial number is not present.
        return build_osquery_conf(MetaMachine(self.machine_serial_number))


class DistributedReadView(BaseNodeView):
    request_type = "distributed_read"

    def do_node_post(self, data):
        queries = {}
        if self.machine_serial_number:
            machine = MetaMachine(self.machine_serial_number)
            queries = DistributedQueryProbeMachine.objects.new_queries_for_machine(machine)
            for query_name, query in get_distributed_inventory_queries(machine, self.ms):
                if query_name in queries:
                    logger.error("Conflict on the distributed query name %s", query_name)
                else:
                    queries[query_name] = query
        return {'queries': queries}


class DistributedWriteView(BaseNodeView):
    request_type = "distributed_write"

    @transaction.non_atomic_requests
    def do_node_post(self, data):
        payloads = []

        def get_probe_pk(key):
            return int(key.split('_')[-1])

        queries = data['queries']
        ps_d = {ps.id: ps
                for ps in ProbeSource.objects.filter(
                    model='OsqueryDistributedQueryProbe',
                    pk__in=[get_probe_pk(k) for k in queries.keys()
                            if not k.startswith(INVENTORY_DISTRIBUTED_QUERY_PREFIX)]
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
                    elif status == 0:
                        payload["error"] = False
                        if val:
                            payload["result"] = val
                        else:
                            payload["empty"] = True
                    else:
                        raise ValueError("Unknown distributed query status '{}'".format(status))
                    payloads.append(payload)
            post_distributed_query_result(self.machine_serial_number,
                                          self.user_agent, self.ip,
                                          payloads)
        if inventory_snapshot:
            self.commit_inventory_query_result(inventory_snapshot)
        return {}


class LogView(BaseNodeView):
    request_type = "log"

    @transaction.non_atomic_requests
    def do_node_post(self, data):
        inventory_results = []
        other_results = []
        data_data = data.pop('data')
        if not isinstance(data_data, list):
            # TODO verify. New since osquery 1.6.4 ?
            data_data = [json.loads(data_data)]
        for r in data_data:
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

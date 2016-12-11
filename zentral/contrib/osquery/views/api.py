import json
import logging
from dateutil import parser
from django.core.exceptions import SuspiciousOperation
from zentral.contrib.inventory.models import MachineSnapshot, MetaMachine
from zentral.core.probes.models import ProbeSource
from zentral.utils.api_views import JSONPostAPIView, verify_secret, APIAuthError
from zentral.contrib.osquery.conf import build_osquery_conf, DEFAULT_ZENTRAL_INVENTORY_QUERY_NAME
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
                            data.get("host_identifier"))
        post_enrollment_event(ms.machine.serial_number,
                              self.user_agent, self.ip,
                              {'action': action})
        return {'node_key': ms.reference}


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
        if auth_err:
            logger.error("APIAuthError %s", auth_err, extra=data)
            raise APIAuthError(auth_err)
        # TODO: Better verification ?
        self.machine_serial_number = self.ms.machine.serial_number
        self.business_unit = self.ms.business_unit

    def do_post(self, data):
        post_request_event(self.machine_serial_number,
                           self.user_agent, self.ip,
                           self.request_type)
        return self.do_node_post(data)


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
        return {'queries': queries}


class DistributedWriteView(BaseNodeView):
    request_type = "distributed_write"

    def do_node_post(self, data):
        payloads = []

        def get_probe_pk(key):
            return int(key.split('_')[-1])

        queries = data['queries']
        ps_d = {ps.id: ps
                for ps in ProbeSource.objects.filter(
                    model='OsqueryDistributedQueryProbe',
                    pk__in=[get_probe_pk(k) for k in queries.keys()]
                )}
        for key, val in queries.items():
            try:
                probe_source = ps_d[get_probe_pk(key)]
            except KeyError:
                logger.error("Unknown distributed query probe %s", key)
            else:
                payload = {'probe': {'id': probe_source.pk,
                                     'name': probe_source.name}}
                try:
                    status = int(data['statuses'][key])
                except KeyError:
                    # osquery < 2.1.2 has no statuses
                    status = 0
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
        return {}


class LogView(BaseNodeView):
    request_type = "log"

    def do_node_post(self, data):
        inventory_results = []
        other_results = []
        data_data = data.pop('data')
        if not isinstance(data_data, list):
            # TODO verify. New since osquery 1.6.4 ?
            data_data = [json.loads(data_data)]
        for r in data_data:
            if r.get('name', None) == DEFAULT_ZENTRAL_INVENTORY_QUERY_NAME:
                inventory_results.append((parser.parse(r['calendarTime']), r['snapshot']))
            else:
                other_results.append(r)
        data['data'] = other_results
        if inventory_results:
            inventory_results.sort(reverse=True)
            last_snapshot = inventory_results[0][1]
            tree = {'source': {'module': self.ms.source.module,
                               'name': self.ms.source.name},
                    'machine': {'serial_number': self.machine_serial_number},
                    'reference': self.ms.reference,
                    'public_ip_address': self.ip}
            if self.business_unit:
                tree['business_unit'] = self.business_unit.serialize()
            for t in last_snapshot:
                table_name = t.pop('table_name')
                if table_name == 'os_version':
                    tree['os_version'] = t
                elif table_name == 'system_info':
                    tree['system_info'] = t
                elif table_name == 'network_interface':
                    tree.setdefault('network_interfaces', []).append(t)
            try:
                MachineSnapshot.objects.commit(tree)
            except:
                logger.exception('Cannot save machine snapshot')
        post_events_from_osquery_log(self.machine_serial_number,
                                     self.user_agent, self.ip, data)
        return {}

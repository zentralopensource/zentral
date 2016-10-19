import logging
import requests
from requests.packages.urllib3.util import Retry
from .base import BaseInventory, InventoryError

logger = logging.getLogger('zentral.contrib.inventory.backends.jss')


class InventoryClient(BaseInventory):
    source_config_secret_attributes = ['user', 'password']

    def __init__(self, config_d):
        super(InventoryClient, self).__init__(config_d)
        self.base_url = 'https://%(host)s:%(port)s' % config_d
        self.api_base_url = '%s%s' % (self.base_url, config_d['path'])
        # requests session setup
        self.session = requests.Session()
        self.session.headers.update({'user-agent': 'zentral/0.0.1',
                                     'accept': 'application/json'})
        self.session.auth = (config_d['user'], config_d['password'])
        max_retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        self.session.mount(self.api_base_url,
                           requests.adapters.HTTPAdapter(max_retries=max_retries))

    def _make_get_query(self, path):
        url = "%s%s" % (self.api_base_url, path)
        try:
            r = self.session.get(url)
        except requests.exceptions.RequestException as e:
            raise InventoryError("JSS API error: %s" % str(e))
        if r.status_code != requests.codes.ok:
            raise InventoryError("JSS API HTTP response status code %s" % r.status_code)
        return r.json()

    def _computergroups(self):
        return self._make_get_query('/computergroups')['computer_groups']

    def _computers(self):
        return self._make_get_query('/computers')['computers']

    def _computer(self, jss_id):
        return self._make_get_query('/computers/id/{}'.format(jss_id))['computer']

    def _machine_links_from_id(self, machine_id):
        ll = []
        for anchor_text, url_tmpl in (('Inventory', "{}/computers.html?id={}&o=r"),
                                      ('Management', "{}/computers.html?id={}&o=r&v=management")):
            ll.append({'anchor_text': anchor_text,
                       'url': url_tmpl.format(self.base_url, machine_id)})
        return ll

    def _group_links_from_id(self, group_id, is_smart):
        if is_smart:
            url_tmpl = "{}/smartComputerGroups.html?id={}&o=r&nav=c"
        else:
            url_tmpl = "{}/staticComputerGroups.html?id={}&o=r&nav=c"
        return [{'anchor_text': 'Group',
                 'url': url_tmpl.format(self.base_url, group_id)}]

    def get_machines(self):
        reverse_computer_groups = {}
        for computer_group in self._computergroups():
            reverse_computer_groups[computer_group['name']] = (computer_group['id'],
                                                               computer_group['is_smart'])
        for machine in self._computers():
            machine_id = machine.pop('id')
            computer = self._computer(machine_id)
            # serial number, reference
            ct = {'reference': str(machine_id),
                  'links': self._machine_links_from_id(machine_id),
                  'machine': {'serial_number': computer['general']['serial_number']}}

            # business unit
            site_id = computer['general']['site']['id']
            if site_id >= 0:
                site_reference = str(site_id)
                site_name = computer['general']['site']['name']
            else:
                site_reference = "DEFAULT"
                site_name = "Default"
            ct['business_unit'] = {'reference': site_reference,
                                   'name': site_name}

            # groups
            groups = []
            cg_names = computer['groups_accounts']['computer_group_memberships']
            org_cg_num = len(cg_names)
            cg_names = set(cg_names)
            if len(cg_names) < org_cg_num:
                logger.warning('Dupplicated group. source %s, machine %s',
                               self.name, machine_id)
            for computer_group_name in cg_names:
                try:
                    group_id, is_smart = reverse_computer_groups[computer_group_name]
                except KeyError:
                    # TODO: Race ?
                    continue
                else:
                    groups.append({'reference': str(group_id),
                                   'name': computer_group_name,
                                   'links': self._group_links_from_id(group_id, is_smart)})
            if groups:
                ct['groups'] = groups

            hardware = computer['hardware']
            # os version
            os_version = dict(zip(('major', 'minor', 'patch'),
                                  (int(s) for s in hardware['os_version'].split('.'))))
            os_version.update({'name': hardware['os_name'],
                               'build': hardware['os_build']})
            ct['os_version'] = os_version

            # system info
            system_info = {'computer_name': computer['general']['name'],
                           'hardware_model': hardware['model_identifier'],
                           'cpu_type': ("{} @{}MHZ".format(hardware['processor_type'],
                                                           hardware['processor_speed_mhz'])).strip(),
                           'cpu_physical_cores': hardware['number_processors'],
                           'physical_memory': computer['hardware']['total_ram'] * 2**20}
            ct['system_info'] = system_info

            # public ip
            last_reported_ip = computer['general'].get('ip_address', None)
            if last_reported_ip:
                ct['public_ip_address'] = last_reported_ip

            # network interfaces
            network_interface = {}
            for attr, ni_attr in (('mac_address', 'mac'),
                                  ('last_reported_ip', 'address')):
                value = computer['general'].get(attr, None)
                if value:
                    network_interface[ni_attr] = value
            if len(network_interface) == 2:
                network_interface['interface'] = 'primary'
                ct['network_interfaces'] = [network_interface]

            # osx apps
            osx_app_instances = []
            for app_d in computer['software']['applications']:
                osx_app_instances.append({'bundle_path': app_d['path'],
                                          'app': {'bundle_name': app_d['name'],
                                                  'bundle_version_str': app_d['version']}})
            ct['osx_app_instances'] = osx_app_instances
            yield ct

    def add_machine_to_group(self, machine_snapshot, group_name):
        source, machine_id = machine_snapshot.source, machine_snapshot.reference
        assert(source.module == self.source['module'] and source.config == self.source['config'])
        machine_id = int(machine_id)
        machine_id_l = []
        try:
            group_d = self._make_get_query('/computergroups/name/{}'.format(group_name))
        except InventoryError:
            group_d = None
        else:
            for computer_d in group_d['computer_group']['computers']:
                machine_id_l.append(computer_d['id'])
        if machine_id in machine_id_l:
            logger.debug("Machine {} already in group {}".format(machine_id, group_name))
            return
        headers = {'content-type': 'text/xml'}
        if group_d:
            url = "%s%s" % (self.api_base_url, "/computergroups/id/{}".format(group_d["computer_group"]["id"]))
            data = ("<computer_group>"
                    "<id>{}</id>"
                    "<computer_additions>"
                    "<computer><id>{}</id></computer>"
                    "</computer_additions>"
                    "</computer_group>").format(group_d["computer_group"]["id"], machine_id)
            r = self.session.put(url, headers=headers, data=data)
        else:
            url = "%s%s" % (self.api_base_url, "/computergroups/id/0")
            data = ("<computer_group>"
                    "<name>{}</name>"
                    "<is_smart>false</is_smart>"
                    "<computers><computer><id>{}</id></computer></computers>"
                    "</computer_group>").format(group_name, machine_id)
            r = self.session.post(url, headers=headers, data=data)
        if r.status_code != requests.codes.created:
            raise InventoryError()

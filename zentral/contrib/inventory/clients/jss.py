import logging
import requests
from .base import BaseInventory, InventoryError

logger = logging.getLogger('zentral.contrib.inventory.backends.jss')


class InventoryClient(BaseInventory):
    def __init__(self, config_d):
        super(InventoryClient, self).__init__(config_d)
        self.base_url = 'https://%(host)s:%(port)s' % config_d
        self.api_base_url = '%s%s' % (self.base_url, config_d['path'])
        self.auth = (config_d['user'], config_d['password'])

    def _make_get_query(self, path):
        url = "%s%s" % (self.api_base_url, path)
        headers = {'user-agent': 'zentral/0.0.1',
                   'accept': 'application/json'}
        r = requests.get(url, headers=headers, auth=self.auth)
        if r.status_code != requests.codes.ok:
            raise InventoryError()
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
                ct['business_unit'] = {'reference': str(site_id),
                                       'name': computer['general']['site']['name']}

            # groups
            groups = []
            for computer_group_name in computer['groups_accounts']['computer_group_memberships']:
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
            os_version = {'name': hardware['os_name'],
                          'build': hardware['os_build']}
            os_version_version = hardware['os_version'].split('.')
            if len(os_version_version) > 0:
                os_version['major'] = os_version_version[0]
                if len(os_version_version) > 1:
                    os_version['minor'] = os_version_version[1]
                    if len(os_version_version) > 2:
                        os_version['patch'] = os_version_version[2]
            ct['os_version'] = os_version

            # system info
            system_info = {'computer_name': computer['general']['name'],
                           'hardware_model': hardware['model_identifier'],
                           'cpu_type': ("{} @{}MHZ".format(hardware['processor_type'],
                                                           hardware['processor_speed_mhz'])).strip(),
                           'cpu_physical_cores': hardware['number_processors'],
                           'physical_memory': computer['hardware']['total_ram'] * 2**20}
            ct['system_info'] = system_info

            # osx apps
            osx_app_instances = []
            for app_d in computer['software']['applications']:
                osx_app_instances.append({'bundle_path': app_d['path'],
                                          'app': {'bundle_name': app_d['name'],
                                                  'bundle_version_str': app_d['version']}})
            ct['osx_app_instances'] = osx_app_instances
            yield ct

    def add_machine_to_group(self, machine_snapshot, group_name):
        if isinstance(machine_snapshot, dict):
            source, machine_id = machine_snapshot['source'], machine_snapshot['reference']
        else:
            source, machine_id = machine_snapshot.source, machine_snapshot.reference
        assert(source == self.source)
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
        headers = {'user-agent': 'zentral/0.0.1',
                   'accept': 'application/json',
                   'content-type': 'text/xml'}
        if group_d:
            url = "%s%s" % (self.api_base_url, "/computergroups/id/{}".format(group_d["computer_group"]["id"]))
            data = ("<computer_group>"
                    "<id>{}</id>"
                    "<computer_additions>"
                    "<computer><id>{}</id></computer>"
                    "</computer_additions>"
                    "</computer_group>").format(group_d["computer_group"]["id"], machine_id)
            r = requests.put(url, headers=headers, auth=self.auth, data=data)
        else:
            url = "%s%s" % (self.api_base_url, "/computergroups/id/0")
            data = ("<computer_group>"
                    "<name>{}</name>"
                    "<is_smart>false</is_smart>"
                    "<computers><computer><id>{}</id></computer></computers>"
                    "</computer_group>").format(group_name, machine_id)
            r = requests.post(url, headers=headers, auth=self.auth, data=data)
        if r.status_code != requests.codes.created:
            raise InventoryError()
        return r.json()

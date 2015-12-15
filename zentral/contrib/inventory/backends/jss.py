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
        self.inv_url_tmpl = "%s/computers.html?id=%%s&o=r" % self.base_url

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

    def _make_reference(self, reference):
        if reference is None:
            raise TypeError
        reference = str(reference)
        if not reference:
            raise ValueError
        return "{}${}${}".format(self.__module__,
                                 self.base_url,
                                 reference)

    def get_machines(self):
        reverse_computer_groups = {}
        for computer_group in self._computergroups():
            reverse_computer_groups[computer_group['name']] = computer_group['id']
        for machine in self._computers():
            inv_reference = machine.pop('id')
            computer = self._computer(inv_reference)
            # serial number, reference
            ct = {'reference': self._make_reference(inv_reference),
                  'machine': {'serial_number': computer['general']['serial_number']}}

            # business unit
            site_id = computer['general']['site']['id']
            if site_id >= 0:
                ct['business_unit'] = {'name': computer['general']['site']['name'],
                                       'reference': self._make_reference(site_id)}

            # groups
            groups = []
            for computer_group_name in computer['groups_accounts']['computer_group_memberships']:
                try:
                    computer_group_id = reverse_computer_groups[computer_group_name]
                except KeyError:
                    # TODO: Race ?
                    continue
                else:
                    groups.append({'reference': self._make_reference(computer_group_id),
                                   'name': computer_group_name})
            if groups:
                ct['groups'] = groups

            hardware = computer['hardware']
            # os_version
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

            # system_info
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
                                                  'version_str': app_d['version']}})
            ct['osx_app_instances'] = osx_app_instances
            yield ct

    def _get_inv_link(self, md):
        return self.inv_url_tmpl % md[self._inv_reference_key()]

    def add_machine_to_group(self, md, group_name):
        inv_ref_key = self._inv_reference_key()
        if inv_ref_key not in md:
            logger.error('Missing inventory reference')
            return
        machine_id = int(md[inv_ref_key])
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

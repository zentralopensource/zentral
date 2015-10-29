from dateutil import parser
import logging
import requests
from .base import BaseInventory, InventoryError

logger = logging.getLogger('zentral.contrib.inventory.backends.jss')


class InventoryClient(BaseInventory):
    def __init__(self, config_d):
        super(InventoryClient, self).__init__(config_d)
        base_url = 'https://%(host)s:%(port)s' % config_d
        self.api_base_url = '%s%s' % (base_url, config_d['path'])
        self.auth = (config_d['user'], config_d['password'])
        self.inv_url_tmpl = "%s/computers.html?id=%%s&o=r" % base_url

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

    def _get_machines(self):
        reverse_computer_groups = {}
        for computer_group in self._computergroups():
            reverse_computer_groups[computer_group['name']] = computer_group['id']
        for machine in self._computers():
            inv_reference = machine.pop('id')
            computer = self._computer(inv_reference)
            machine[self._inv_reference_key()] = inv_reference
            machine['serial_number'] = computer['general']['serial_number']
            machine['last_contact_at'] = parser.parse(computer['general']['last_contact_time_utc'])
            machine['last_report_at'] = parser.parse(computer['general']['report_date_utc'])
            machine['groups'] = []
            machine['public_ip_address'] = computer['general']['ip_address']
            site_id = computer['general']['site']['id']
            if site_id >= 0:
                machine['groups'].append({'key': 'site_{}'.format(site_id),
                                          'name': computer['general']['site']['name']})
            for computer_group_name in computer['groups_accounts']['computer_group_memberships']:
                try:
                    computer_group_id = reverse_computer_groups[computer_group_name]
                except KeyError:
                    # TODO: Race ?
                    continue
                else:
                    machine['groups'].append({'key': 'computer_group_{}'.format(computer_group_id),
                                              'name': computer_group_name})
            for hw_attr in ['make', 'model', 'os_name', 'os_version', 'os_build', 'processor_type', 'processor_speed']:
                machine[hw_attr] = computer['hardware'][hw_attr]
            machine['ram_total'] = computer['hardware']['total_ram'] * 2**20
            machine['hd_number'] = 0
            machine['hd_space'] = 0
            machine['hd_total'] = 0
            machine['hd_encrypted'] = 0
            for disk in computer['hardware']['storage']:
                machine['hd_number'] += 1
                try:
                    partition = disk['partition']
                except KeyError:
                    # TODO: Why ?
                    continue
                machine['hd_space'] += partition['size'] * 2**20
                machine['hd_total'] += partition['size'] * 2**20 * partition['percentage_full'] // 100
                machine['hd_encrypted'] += partition['size'] * 2**20 * partition['filevault2_percent'] // 100
            if machine['hd_space']:
                machine['hd_usage'] = machine['hd_total'] * 100 // machine['hd_space']
                machine['encryption_status'] = machine['hd_encrypted'] * 100 // machine['hd_space']
            else:
                machine['hd_usage'] = 0
                machine['encryption_status'] = 0
            apps = []
            for app_d in computer['software']['applications']:
                # list and not tuple because of json serialization comparison for update.
                # TODO verify
                apps.append([app_d['name'], app_d['version']])
            apps.sort(key=lambda t: (t[0].upper(), t[1]))
            machine['osx_apps'] = apps
            yield machine

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

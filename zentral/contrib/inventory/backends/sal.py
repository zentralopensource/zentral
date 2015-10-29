from dateutil import parser
import logging
import requests
from .base import BaseInventory, InventoryError

logger = logging.getLogger('zentral.contrib.inventory.backends.sal')


class InventoryClient(BaseInventory):
    def __init__(self, config_d):
        super(InventoryClient, self).__init__(config_d)
        base_url = 'http%s://%s' % (config_d.get('secure', True) * 's', config_d['host'])
        self.api_base_url = '%s/api' % base_url
        self.public_key, self.private_key = config_d['public_key'], config_d['private_key']
        self.inv_url_tmpl = "%s/machine_detail/%%s/" % base_url

    def _make_get_query(self, path):
        url = "%s%s" % (self.api_base_url, path)
        headers = {'privatekey': self.private_key,
                   'publickey': self.public_key}
        r = requests.get(url, headers=headers)
        if r.status_code != requests.codes.ok:
            raise InventoryError()
        return r.json()

    def _get_machines(self):
        for sal_machine in self._make_get_query('/machines/'):
            machine_serial = sal_machine['serial']
            last_checkin = parser.parse(sal_machine['last_checkin'])
            machine = {'serial_number': machine_serial,
                       'public_ip_address': "0.0.0.0",  # TODO
                       'name': sal_machine['hostname'].strip(),
                       'make': '?',  # TODO
                       'os_build': '?',  # TODO
                       'model': sal_machine['machine_model'],
                       'last_contact_at': last_checkin,
                       'last_report_at': last_checkin,
                       'os_name': sal_machine['os_family'],
                       'os_version': sal_machine['operating_system'],
                       'processor_type': sal_machine['cpu_type'],
                       'ram_total': sal_machine['memory_kb'] * 2**10,
                       }
            machine[self._inv_reference_key()] = machine_serial  # TODO get sal id from API. Not yet available.
            # Proc speed
            try:
                sal_cpu_speed_freq, sal_cpu_speed_unit = sal_machine['cpu_speed'].upper().split(' ')
                if sal_cpu_speed_unit == 'GHZ':
                    machine['processor_speed'] = int(1000 * float(sal_cpu_speed_freq))
                elif sal_cpu_speed_unit == 'MHZ':
                    machine['processor_speed'] = int(sal_cpu_speed_freq)
            except (ValueError, KeyError):
                logger.error('Could not get machine %s processor speed', machine_serial)
            # Group
            sal_group_id = sal_machine.get('machine_group', None)
            if sal_group_id:
                sal_group = self._make_get_query('/machine_groups/{}/'.format(sal_group_id))
                machine['groups'] = [{'key': sal_group['key'],
                                      'name': sal_group['name']}]
            # HD
            # TODO: encryption status. Not in standard sal API.
            machine['hd_number'] = 1
            machine['hd_encrypted'] = 0
            machine['hd_space'] = int(sal_machine['hd_total']) * 2**10
            hd_free = int(sal_machine['hd_space']) * 2**10
            machine['hd_total'] = machine['hd_space'] - hd_free
            if machine['hd_space']:
                machine['hd_usage'] = machine['hd_total'] * 100 // machine['hd_space']
                machine['encryption_status'] = machine['hd_encrypted'] * 100 // machine['hd_space']
            else:
                machine['hd_usage'] = 0
                machine['encryption_status'] = 0
            # APPS
            apps = []
            for sal_inventory_item in self._make_get_query('/machines/{}/inventory/'.format(machine_serial)):
                # list and not tuple because of json serialization comparison for update.
                # TODO verify
                apps.append([sal_inventory_item['name'], sal_inventory_item['version']])
            apps.sort(key=lambda t: (t[0].upper(), t[1]))
            machine['osx_apps'] = apps
            yield machine

    def _get_inv_link(self, md):
        return self.inv_url_tmpl % md[self._inv_reference_key()]

    def add_machine_to_group(self, md, group_name):
        raise NotImplementedError

from dateutil import parser
import logging
import requests
from .base import BaseInventory, InventoryError

logger = logging.getLogger('zentral.contrib.inventory.backends.sal')


class InventoryClient(BaseInventory):
    def __init__(self, config_d):
        super(InventoryClient, self).__init__(config_d)
        self.base_url = 'http{}://{}'.format(config_d.get('secure', True) * 's', config_d['host'])
        self.api_base_url = '{}/api'.format(self.base_url)
        self.public_key, self.private_key = config_d['public_key'], config_d['private_key']

    def _make_get_query(self, path):
        url = "%s%s" % (self.api_base_url, path)
        headers = {'privatekey': self.private_key,
                   'publickey': self.public_key}
        r = requests.get(url, headers=headers)
        if r.status_code != requests.codes.ok:
            raise InventoryError()
        return r.json()

    def _reference_from_machine_id(self, machine_id):
        if machine_id is None:
            raise TypeError
        machine_id = str(machine_id)
        if not machine_id:
            raise ValueError
        return "{}${}${}".format(self.source,
                                 self.base_url,
                                 machine_id)

    def get_machine_link_from_reference(self, reference):
        source, base_url, machine_id = reference.split('$')
        assert(source == self.source)
        return "{}/machine_detail/{}/".format(base_url, machine_id)

    def get_machines(self):
        for sal_machine in self._make_get_query('/machines/'):
            machine_id = sal_machine['serial']  # serial number == machine_id in this client
            ct = {'reference': self._reference_from_machine_id(machine_id),
                  'machine': {'serial_number': machine_id}}

            # groups
            sal_group_id = sal_machine.get('machine_group', None)
            if sal_group_id:
                sal_group = self._make_get_query('/machine_groups/{}/'.format(sal_group_id))
                ct['groups'] = [{'reference': sal_group['key'],
                                 'name': sal_group['name']}]

            # os version
            os_version = {'name': sal_machine['os_family']}
            try:
                os_version['major'], os_version['minor'], os_version['patch'] = (int(p) for p in sal_machine['operating_system'].split("."))
            except:
                raise
            else:
                ct['os_version'] = os_version

            # system info
            cpu_speed = sal_machine.get('cpu_speed', None)
            ct['system_info'] = {'computer_name': sal_machine['hostname'].strip(),
                                 'hardware_model': sal_machine['machine_model'],
                                 'cpu_type': " @".join((s for s in (sal_machine.get(k) for k in ('cpu_type', 'cpu_speed')) if s)),
                                 'physical_memory': sal_machine['memory_kb'] * 2**10}

            yield ct

    def add_machine_to_group(self, md, group_name):
        raise NotImplementedError

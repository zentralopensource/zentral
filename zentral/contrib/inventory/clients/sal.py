import logging
import requests
from requests.packages.urllib3.util import Retry
from .base import BaseInventory, InventoryError

logger = logging.getLogger('zentral.contrib.inventory.backends.sal')


class InventoryClient(BaseInventory):
    source_config_secret_attributes = ['private_key']

    def __init__(self, config_d):
        super(InventoryClient, self).__init__(config_d)
        self.base_url = 'http{}://{}'.format(config_d.get('secure', True) * 's', config_d['host'])
        self.api_base_url = '{}/api'.format(self.base_url)
        self.public_key, self.private_key = config_d['public_key'], config_d['private_key']
        # requests session setup
        self.session = requests.Session()
        self.session.headers.update({'user-agent': 'zentral/0.0.1',
                                     'accept': 'application/json',
                                     'privatekey': self.private_key,
                                     'publickey': self.public_key})
        max_retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        self.session.mount(self.api_base_url,
                           requests.adapters.HTTPAdapter(max_retries=max_retries))

    def _make_get_query(self, path):
        url = "%s%s" % (self.api_base_url, path)
        try:
            r = self.session.get(url)
        except requests.exceptions.RequestException as e:
            raise InventoryError("Sal API error: %s" % str(e))
        if r.status_code != requests.codes.ok:
            raise InventoryError("Sal API HTTP response status code %s" % r.status_code)
        return r.json()

    def _machine_links_from_id(self, machine_id):
        return [{"anchor_text": "Machine Detail",
                 "url": "{}/machine_detail/{}/".format(self.base_url, machine_id)}]

    def _group_links_from_id(self, group_id):
        return [{"anchor_text": "Machine Group",
                 "url": "{}/machinegroup/{}/".format(self.base_url, group_id)}]

    def _bu_links_from_id(self, bu_id):
        return [{"anchor_text": "Dashboard",
                 "url": "{}/dashboard/{}/".format(self.base_url, bu_id)}]

    def get_machines(self):
        for sal_machine in self._make_get_query('/machines/'):
            machine_id = sal_machine['serial']  # serial number == machine_id in this client
            ct = {'reference': machine_id,
                  'links': self._machine_links_from_id(machine_id),
                  'serial_number': machine_id}

            # groups
            sal_group_id = sal_machine.get('machine_group', None)
            if sal_group_id:
                sal_group = self._make_get_query('/machine_groups/{}/'.format(sal_group_id))
                ct['groups'] = [{'reference': str(sal_group_id),
                                 'name': sal_group['name'],
                                 'links': self._group_links_from_id(sal_group_id)}]
                business_unit_id = int(sal_group['business_unit'])
                business_unit = self._make_get_query('/business_units/{}/'.format(business_unit_id))
                ct['business_unit'] = {'reference': str(business_unit_id),
                                       'name': business_unit['name'],
                                       'links': self._bu_links_from_id(business_unit_id)}

            # os version
            os_version = dict(zip(('major', 'minor', 'patch'),
                                  (int(p) for p in sal_machine['operating_system'].split("."))))
            os_version['name'] = sal_machine['os_family']
            ct['os_version'] = os_version

            # system info
            ct['system_info'] = {'computer_name': sal_machine['hostname'].strip(),
                                 'hardware_model': sal_machine['machine_model'],
                                 'cpu_type': " @".join((s for s in (sal_machine.get(k)
                                                                    for k in ('cpu_type', 'cpu_speed'))
                                                        if s)),
                                 'physical_memory': sal_machine['memory_kb'] * 2**10}

            yield ct

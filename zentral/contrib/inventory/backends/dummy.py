from datetime import datetime, timedelta
import logging
import random
from .base import BaseInventory

logger = logging.getLogger('zentral.contrib.inventory.backends.dummy')

DUMMY_MACHINES = [
    {'serial_number': '0123456789',
     'public_ip_address': '8.8.8.8',
     'name': 'dummy1',
     'make': 'Apple',
     'os_build': '1234',
     'model': 'MacBook1,2',
     'os_name': 'Darwin',
     'os_version': '10.10',
     'processor_type': 'Intel Core M',
     'processor_speed': 1300,
     'ram_total': 8 * 2**30,
     'hd_number': 1,
     'hd_total': 123456 * 2**20,
     'hd_space': 256 * 2**30,
     'hd_encrypted': 256 * 2**30,
     'groups': [{'key': 'dummy_group_1',
                 'name': 'Dummy Group 1'}],
     'osx_apps': [['Dummy App', '1.0']]},
    {'serial_number': '9876543210',
     'public_ip_address': '8.8.4.4',
     'name': 'dummy2',
     'make': 'Apple',
     'os_build': '2345',
     'model': 'MacBook2,3',
     'os_name': 'Darwin',
     'os_version': '10.11',
     'processor_type': 'Intel Core M',
     'processor_speed': 1500,
     'ram_total': 16 * 2**30,
     'hd_number': 1,
     'hd_total': 234561 * 2**20,
     'hd_space': 512 * 2**30,
     'hd_encrypted': 512 * 2**30,
     'groups': [{'key': 'dummy_group_2',
                 'name': 'Dummy Group 2'}],
     'osx_apps': [['Dummy App', '2.0']]},
]


class InventoryClient(BaseInventory):
    def __init__(self, config_d):
        super(InventoryClient, self).__init__(config_d)

    def _get_machines(self):
        for machine_d in DUMMY_MACHINES:
            now = datetime.utcnow()
            # hd usage / encryption status
            if machine_d['hd_space']:
                machine_d['hd_usage'] = machine_d['hd_total'] * 100 // machine_d['hd_space']
                machine_d['encryption_status'] = machine_d['hd_encrypted'] * 100 // machine_d['hd_space']
            else:
                machine_d['hd_usage'] = 0
                machine_d['encryption_status'] = 0
            # timestamps
            for attr in ('last_contact_at', 'last_report_at'):
                val = machine_d.get(attr, None)
                if val is None:
                    # sometime in the past
                    val = now + timedelta(seconds=random.randint(-10000, -100))
                elif random.randint(0, 100) > 66:  # 1/3 chance
                    # sometime between the last value and now
                    age = (now - val).seconds
                    val = val + timedelta(seconds=random.randint(0, age))
                machine_d[attr] = val
            yield machine_d

    def add_machine_to_group(self, md, group_name):
        raise NotImplementedError

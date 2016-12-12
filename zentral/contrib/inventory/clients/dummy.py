import logging
from .base import BaseInventory

logger = logging.getLogger('zentral.contrib.inventory.backends.dummy')

DUMMY_MACHINES = [
    {'serial_number': '0123456789',
     'groups': [{'reference': 'dummy_group_1',
                 'name': 'Dummy Group 1'}],
     'os_version': {'name': 'OSX',
                    'build': 'Build1',
                    'major': 10,
                    'minor': 11,
                    'patch': 1},
     'system_info': {'computer_name': 'dummy1',
                     'hardware_model': 'MacBook1,2',
                     'cpu_type': "Intel Core M @ 1.3GHz",
                     'cpu_physical_cores': 2,
                     'physical_memory': 8 * 2**30},
     'osx_app_instances': [{'app': {'bundle_name': 'Dummy.app', 'bundle_version_str': '1.0'}}],
     },
    {'serial_number': '9876543210',
     'groups': [{'reference': 'dummy_group_2',
                 'name': 'Dummy Group 2'}],
     'os_version': {'name': 'OSX',
                    'build': 'Build2',
                    'major': 10,
                    'minor': 11,
                    'patch': 2},
     'system_info': {'computer_name': 'dummy2',
                     'hardware_model': 'MacBook2,1',
                     'cpu_type': "Intel Core M @ 1.3GHz",
                     'cpu_physical_cores': 2,
                     'physical_memory': 8 * 2**30},
     'osx_app_instances': [{'app': {'bundle_name': 'Dummy.app', 'bundle_version_str': '2.0'}}],
     }
]


class InventoryClient(BaseInventory):
    def __init__(self, config_d):
        super(InventoryClient, self).__init__(config_d)

    def get_machines(self):
        for idx, machine_snapshot_d in enumerate(DUMMY_MACHINES):
            machine_snapshot_d['reference'] = '{}${}'.format(self.__module__, idx)
            yield machine_snapshot_d

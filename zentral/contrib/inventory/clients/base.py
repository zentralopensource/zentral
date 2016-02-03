import copy
from django.db import transaction
from zentral.contrib.inventory.models import MachineSnapshot

__all__ = ['BaseInventory', 'InventoryError']


class InventoryError(Exception):
    pass


class BaseInventory(object):
    source_config_secret_attributes = None

    def __init__(self, config_d):
        if not hasattr(self, 'name'):
            self.name = self.__module__.split('.')[-1]
        config_d = copy.deepcopy(config_d)
        config_d.pop('backend')
        if self.source_config_secret_attributes:
            for attr in self.source_config_secret_attributes:
                config_d.pop(attr, None)
        self.source = {'module': self.__module__,
                       'name': self.name,
                       'config': config_d}

    def get_machines(self):
        raise NotImplementedError

    # inventory API
    def sync(self):
        for machine_d in self.get_machines():
            source = copy.deepcopy(self.source)
            # source will be modified by mto
            machine_d['source'] = source
            for group_d in machine_d.get('groups', []):
                group_d['source'] = source
            business_unit_d = machine_d.get('business_unit', None)
            if business_unit_d:
                business_unit_d['source'] = source
            with transaction.atomic():
                machine_snapshot, created = MachineSnapshot.objects.commit(machine_d)
            if created:
                action = "changed"
                key = "diff"
                data = machine_snapshot.update_diff()
                if data is None:
                    action = "added"
                    key = "added"
                    data = machine_snapshot.serialize()
                yield machine_snapshot, {'action': action, 'source': self.source, key: data}

    def add_machine_to_group(self, machine_snapshot, group_name):
        raise NotImplementedError

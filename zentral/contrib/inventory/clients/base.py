import copy
from zentral.contrib.inventory.models import MachineSnapshot

__all__ = ['BaseInventory', 'InventoryError']


class InventoryError(Exception):
    pass


class BaseInventory(object):
    def __init__(self, config_d):
        if not hasattr(self, 'name'):
            self.name = self.__module__.split('.')[-1]
        config_d = copy.deepcopy(config_d)
        config_d.pop('backend')
        self.source = {'module': self.__module__,
                       'name': self.name,
                       'config': config_d}

    def get_machines(self):
        raise NotImplementedError

    # inventory API
    def sync(self):
        for machine_d in self.get_machines():
            machine_d['source'] = self.source
            for group_d in machine_d.get('groups', []):
                group_d['source'] = self.source
            business_unit_d = machine_d.get('business_unit', None)
            if business_unit_d:
                business_unit_d['source'] = self.source
            machine_snapshot, created = MachineSnapshot.objects.commit(machine_d)
            if created:
                update_diff = machine_snapshot.update_diff()
                if update_diff is None:
                    yield machine_snapshot, {'action': 'added',
                                             'diff': machine_snapshot.serialize()}
                elif update_diff:
                    yield machine_snapshot, {'action': 'changed',
                                             'diff': update_diff}

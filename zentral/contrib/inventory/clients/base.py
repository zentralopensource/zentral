import json
from zentral.contrib.inventory.models import MachineSnapshot

__all__ = ['BaseInventory', 'InventoryError']


class InventoryError(Exception):
    pass


class BaseInventory(object):
    def __init__(self, config_d):
        self.source = self.__module__
        if not hasattr(self, 'name'):
            self.name = self.source.split('.')[-1]

    def get_machines(self):
        raise NotImplementedError

    # inventory API
    def sync(self):
        for machine_d in self.get_machines():
            machine_d['source'] = self.source
            machine_snapshot, created = MachineSnapshot.objects.commit(machine_d)
            if created:
                update_diff = machine_snapshot.update_diff()
                if update_diff is None:
                    yield machine_snapshot, {'action': 'added',
                                             'diff': machine_snapshot.serialize()}
                elif update_diff:
                    yield machine_snapshot, {'action': 'changed',
                                             'diff': update_diff}

    def machines(self):
        qs = MachineSnapshot.objects.select_related('machine',
                                                    'business_unit',
                                                    'os_version',
                                                    'system_info')
        qs = qs.prefetch_related('groups',
                                 'osx_app_instances__app',
                                 'osx_app_instances__signed_by')
        return qs.filter(source=self.source,
                         mt_next__isnull=True)

    def machine(self, msn):
        try:
            return self.machines().get(machine__serial_number=msn)
        except MachineSnapshot.DoesNotExist:
            pass

    def serializable_machine(self, msn):
        machine = self.machine(msn)
        return json.dumps(machine.serialize())

    # Metrics
    def _osx_apps_gauges(self):
        c = {}
        for ms in self.machines():
            for osx_app_instance in ms.osx_app_instances.all():
                key = frozenset(osx_app_instance.app.serialize().items())
                c[key] = c.setdefault(key, 0) + 1
        return c

    def _os_gauges(self):
        c = {}
        for ms in self.machines().filter(os_version__isnull=False):
            key = frozenset(ms.os_version.serialize().items())
            c[key] = c.setdefault(key, 0) + 1
        return c

    def metrics(self):
        return [{'name': 'zentral_inventory_osx_apps_sum',
                 'help_text': 'Zentral inventory OSX apps versions',
                 'gauges': self._osx_apps_gauges()},
                {'name': 'zentral_inventory_os_versions_sum',
                 'help_text': 'Zentral inventory OS versions',
                 'gauges': self._os_gauges()}]

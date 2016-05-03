import copy
import logging
from django.db import transaction
from zentral.contrib.inventory.models import MachineSnapshot

__all__ = ['BaseInventory', 'InventoryError']

logger = logging.getLogger('zentral.contrib.inventory.clients.base')


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
    def _events_from_diff(self, diff):
        events = []
        for m2m_attr, event_type in (('links', 'inventory_link_update'),
                                     ('osx_app_instances', 'inventory_osx_app_instance_update'),
                                     ('groups', 'inventory_group_update')):
            m2m_diff = diff.get(m2m_attr, {})
            for action in ['added', 'removed']:
                for obj in m2m_diff.get(action, []):
                    obj['action'] = action
                    if 'source' not in obj:
                        obj['source'] = self.source
                    events.append((event_type, obj))
        for fk_attr in ('reference',
                        'machine',
                        'business_unit',
                        'os_version',
                        'system_info',
                        'teamviewer'):
            event_type = 'inventory_{}_update'.format(fk_attr)
            fk_diff = diff.get(fk_attr, {})
            for action in ['added', 'removed']:
                obj = fk_diff.get(action, None)
                if obj:
                    if isinstance(obj, dict):
                        event = obj
                        if 'source' not in obj:
                            event['source'] = self.source
                    else:
                        event = {'source': self.source,
                                 fk_attr: obj}
                    event['action'] = action
                    events.append((event_type, event))
        return events

    def sync(self):
        for machine_d in self.get_machines():
            source = copy.deepcopy(self.source)
            try:
                serial_number = machine_d['machine']['serial_number']
            except KeyError:
                logger.warning('Machine w/o serial number. Client "%s". Reference "%s"',
                               self.name, machine_d.get('reference', 'Unknown'))
                continue
            if not serial_number:
                logger.warning('Machine serial number blank. Client "%s". Reference "%s"',
                               self.name, machine_d.get('reference', 'Unknown'))
                continue
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
                diff = machine_snapshot.update_diff()
                if diff is None:
                    events = [('inventory_machine_added',
                               {'source': self.source,
                                'machine_snapshot': machine_snapshot.serialize()})]
                else:
                    events = self._events_from_diff(diff)
                yield machine_snapshot, events

    def add_machine_to_group(self, machine_snapshot, group_name):
        raise NotImplementedError

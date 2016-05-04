import logging
from zentral.core.actions.backends.base import BaseAction
from zentral.contrib.inventory.models import Tag, MachineTag

logger = logging.getLogger('zentral.contrib.inventory.actions.machine_tag')


class Action(BaseAction):
    def trigger(self, event, probe, action_config_d):
        msn = event.metadata.machine_serial_number
        tag = Tag.objects.get(pk=action_config_d['tag_id'])
        action = action_config_d['action']
        if action == 'add':
            MachineTag.objects.get_or_create(serial_number=msn, tag=tag)
        elif action == 'remove':
            MachineTag.objects.filter(serial_number=msn, tag=tag).delete()
        else:
            raise ValueError("Unknown action '%s'" % action)

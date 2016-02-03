from zentral.core.events import BaseEvent, EventMetadata, register_event_type
import logging

logger = logging.getLogger('zentral.contrib.inventory.events')


class InventoryUpdateEvent(BaseEvent):
    event_type = "inventory_update"

register_event_type(InventoryUpdateEvent)


def _inventory_event_tags_from_data(data):
    tags = []
    if data['action'] == 'added':
        tags.append('new_machine')
        return tags
    # action == 'changed'
    if 'diff' not in data:
        logger.error('Unknown data structure')
        return tags
    diff = data['diff']
    if 'groups' in diff:
        tags.append('group_change')
    if 'osx_app_instances' in diff:
        tags.append('osx_app_change')
    if 'os_version' in diff:
        tags.append('os_change')
    return tags


def post_inventory_event(msn, data, uuid, index):
    event_cls = InventoryUpdateEvent
    tags = _inventory_event_tags_from_data(data)
    metadata = EventMetadata(event_cls.event_type,
                             machine_serial_number=msn,
                             uuid=uuid,
                             index=index,
                             tags=tags)
    event = event_cls(metadata, data)
    event.post()

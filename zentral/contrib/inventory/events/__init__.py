from zentral.core.events import BaseEvent, EventMetadata, register_event_type


class InventoryUpdateEvent(BaseEvent):
    event_type = "inventory_update"

register_event_type(InventoryUpdateEvent)


def post_inventory_event(msn, data, uuid, index):
    event_cls = InventoryUpdateEvent
    metadata = EventMetadata(event_cls.event_type,
                             machine_serial_number=msn,
                             uuid=uuid,
                             index=index)
    event = event_cls(metadata, data)
    event.post()

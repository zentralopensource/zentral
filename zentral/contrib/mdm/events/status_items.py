import logging
from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent, EventMetadata


logger = logging.getLogger('zentral.contrib.mdm.events.status_items')


class StatusItemsUpdateEvent(BaseEvent):
    event_type = "mdm_status_items_update"
    tags = ["mdm"]

    def get_linked_objects_keys(self):
        keys = {}
        software_update_enforcement = self.payload.get("software_update_enforcement")
        if software_update_enforcement:
            keys["mdm_software_update_enforcement"] = [(software_update_enforcement["pk"],)]
        enrolled_user = self.payload.get("enrolled_user")
        if enrolled_user:
            keys["mdm_enrolled_user"] = [(enrolled_user["pk"],)]
        return keys


register_event_type(StatusItemsUpdateEvent)


def post_status_items_update_event(target, payload):
    event_metadata = EventMetadata(machine_serial_number=target.serial_number)
    event = StatusItemsUpdateEvent(event_metadata, payload)
    event.post()

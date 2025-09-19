import logging
from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent, EventMetadata


logger = logging.getLogger('zentral.contrib.mdm.events.admin_password')


class AdminPasswordUpdatedEvent(BaseEvent):
    event_type = "admin_password_updated"
    tags = ["mdm", "admin_password"]

    def get_linked_objects_keys(self):
        keys = {}
        cmd_uuid = self.payload.get("command", {}).get("uuid")
        if cmd_uuid:
            keys["mdm_command"] = [(cmd_uuid,)]
        return keys


register_event_type(AdminPasswordUpdatedEvent)


def post_admin_password_updated_event(mdm_command):
    event_metadata = EventMetadata(
        machine_serial_number=mdm_command.enrolled_device.serial_number,
    )
    event = AdminPasswordUpdatedEvent(
        event_metadata,
        {"command": {"request_type": mdm_command.request_type,
                     "uuid": str(mdm_command.uuid)}},
    )
    event.post()

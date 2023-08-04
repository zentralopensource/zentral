import logging
from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent, EventMetadata


logger = logging.getLogger('zentral.contrib.mdm.events.filevault')


class FileVaultPRKUpdatedEvent(BaseEvent):
    event_type = "filevault_prk_updated"
    tags = ["mdm"]

    def get_linked_objects_keys(self):
        keys = {}
        cmd_uuid = self.payload.get("command", {}).get("uuid")
        if cmd_uuid:
            keys["mdm_command"] = [(cmd_uuid,)]
        return keys


register_event_type(FileVaultPRKUpdatedEvent)


def post_filevault_prk_updated_event(mdm_command):
    event_metadata = EventMetadata(
        machine_serial_number=mdm_command.enrolled_device.serial_number,
    )
    event = FileVaultPRKUpdatedEvent(
        event_metadata,
        {"command": {"request_type": mdm_command.request_type,
                     "uuid": str(mdm_command.uuid)}},
    )
    event.post()

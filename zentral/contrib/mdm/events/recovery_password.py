import logging
from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent, EventMetadata


logger = logging.getLogger('zentral.contrib.mdm.events.recovery_password')


class BaseRecoveryPasswordEvent(BaseEvent):
    namespace = "mdm_recovery_password"
    tags = ["mdm", "recovery_password"]

    def get_linked_objects_keys(self):
        keys = {}
        cmd_uuid = self.payload.get("command", {}).get("uuid")
        if cmd_uuid:
            keys["mdm_command"] = [(cmd_uuid,)]
        return keys


class RecoveryPasswordSetEvent(BaseRecoveryPasswordEvent):
    event_type = "recovery_password_set"


register_event_type(RecoveryPasswordSetEvent)


class RecoveryPasswordUpdatedEvent(BaseRecoveryPasswordEvent):
    event_type = "recovery_password_updated"


register_event_type(RecoveryPasswordUpdatedEvent)


class RecoveryPasswordClearedEvent(BaseRecoveryPasswordEvent):
    event_type = "recovery_password_cleared"


register_event_type(RecoveryPasswordClearedEvent)


def post_recovery_password_event(mdm_command, password_type, operation):
    event_metadata = EventMetadata(
        machine_serial_number=mdm_command.enrolled_device.serial_number,
    )
    if operation == "set":
        event_class = RecoveryPasswordSetEvent
    elif operation == "update":
        event_class = RecoveryPasswordUpdatedEvent
    elif operation == "clear":
        event_class = RecoveryPasswordClearedEvent
    else:
        raise ValueError(f"Unknown recovery password operation: {operation}")
    event = event_class(
        event_metadata,
        {"command": {"request_type": mdm_command.request_type,
                     "uuid": str(mdm_command.uuid)},
         "password_type": password_type},
    )
    event.post()

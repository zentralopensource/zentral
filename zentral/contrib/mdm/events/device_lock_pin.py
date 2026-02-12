import logging

from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent, EventMetadata

logger = logging.getLogger('zentral.contrib.mdm.events.device_lock_pin')


class BaseDeviceLockPinEvent(BaseEvent):
    namespace = "mdm_device_lock_pin"
    tags = ["mdm", "device_lock_pin"]

    def get_linked_objects_keys(self):
        keys = {}
        cmd_uuid = self.payload.get("command", {}).get("uuid")
        if cmd_uuid:
            keys["mdm_command"] = [(cmd_uuid,)]
        return keys


class DeviceLockPinSetEvent(BaseDeviceLockPinEvent):
    event_type = "device_lock_pin_set"


register_event_type(DeviceLockPinSetEvent)


class DeviceLockPinUpdatedEvent(BaseDeviceLockPinEvent):
    event_type = "device_lock_pin_updated"


register_event_type(DeviceLockPinUpdatedEvent)


class DeviceLockPinClearedEvent(BaseDeviceLockPinEvent):
    event_type = "device_lock_pin_cleared"


register_event_type(DeviceLockPinClearedEvent)


def post_device_lock_pin_event(mdm_command, password_type, operation):
    event_metadata = EventMetadata(
        machine_serial_number=mdm_command.enrolled_device.serial_number,
    )
    if operation == "set":
        event_class = DeviceLockPinSetEvent
    elif operation == "update":
        event_class = DeviceLockPinUpdatedEvent
    elif operation == "clear":
        event_class = DeviceLockPinClearedEvent
    else:
        raise ValueError(f"Unknown recovery password operation: {operation}")
    event = event_class(
        event_metadata,
        {"command": {"request_type": mdm_command.request_type,
                     "uuid": str(mdm_command.uuid)},
         "password_type": password_type},
    )
    event.post()

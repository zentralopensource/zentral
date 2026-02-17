import logging

from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent, EventMetadata, EventRequest

logger = logging.getLogger("zentral.contrib.mdm.events.device_lock_pin")


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


class DeviceLockPinClearedEvent(BaseDeviceLockPinEvent):
    event_type = "device_lock_pin_cleared"


register_event_type(DeviceLockPinClearedEvent)


def post_device_lock_pin_clear_event(enrolled_device, request):
    DeviceLockPinClearedEvent(
        EventMetadata(
            machine_serial_number=enrolled_device.serial_number,
            request=EventRequest.build_from_request(request),
        ), {}
    ).post()


def post_device_lock_pin_set_event(mdm_command):
    DeviceLockPinSetEvent(
        EventMetadata(
            machine_serial_number=mdm_command.enrolled_device.serial_number,
        ),
        {
            "command": {
                "request_type": mdm_command.request_type,
                "uuid": str(mdm_command.uuid),
            },
        },
    ).post()

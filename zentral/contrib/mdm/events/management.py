import logging

from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent, EventMetadata, EventRequest

logger = logging.getLogger('zentral.contrib.mdm.events.management')


# Admin password


class AdminPasswordViewedEvent(BaseEvent):
    event_type = "admin_password_viewed"
    tags = ["mdm", "admin_password"]


register_event_type(AdminPasswordViewedEvent)


def post_admin_password_viewed_event(request, enrolled_device):
    event_metadata = EventMetadata(
        machine_serial_number=enrolled_device.serial_number,
        request=EventRequest.build_from_request(request),
    )
    event = AdminPasswordViewedEvent(event_metadata, {})
    event.post()


# FileVault PRK


class FileVaultPRKViewedEvent(BaseEvent):
    event_type = "filevault_prk_viewed"
    tags = ["mdm"]


register_event_type(FileVaultPRKViewedEvent)


def post_filevault_prk_viewed_event(request, enrolled_device):
    event_metadata = EventMetadata(
        machine_serial_number=enrolled_device.serial_number,
        request=EventRequest.build_from_request(request),
    )
    event = FileVaultPRKViewedEvent(event_metadata, {})
    event.post()


# Recovery password


class RecoveryPasswordViewedEvent(BaseEvent):
    event_type = "recovery_password_viewed"
    tags = ["mdm"]


register_event_type(RecoveryPasswordViewedEvent)


def post_recovery_password_viewed_event(request, enrolled_device):
    event_metadata = EventMetadata(
        machine_serial_number=enrolled_device.serial_number,
        request=EventRequest.build_from_request(request),
    )
    event = RecoveryPasswordViewedEvent(event_metadata, {})
    event.post()


# Device lock pin


class DeviceLockPinViewedEvent(BaseEvent):
    event_type = "device_lock_pin_viewed"
    tags = ["mdm"]


register_event_type(DeviceLockPinViewedEvent)


def post_device_lock_pin_viewed_event(request, enrolled_device):
    event_metadata = EventMetadata(
        machine_serial_number=enrolled_device.serial_number,
        request=EventRequest.build_from_request(request),
    )
    event = DeviceLockPinViewedEvent(event_metadata, {})
    event.post()


# DEP device


class DEPDeviceDisownedEvent(BaseEvent):
    event_type = "dep_device_disowned"
    tags = ["mdm"]


register_event_type(DEPDeviceDisownedEvent)


def post_dep_device_disowned_event(request, dep_device, payload):
    event_metadata = EventMetadata(
        machine_serial_number=dep_device.serial_number,
        request=EventRequest.build_from_request(request),
    )
    event = DEPDeviceDisownedEvent(event_metadata, payload)
    event.post()

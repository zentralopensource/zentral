import logging
from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent, EventMetadata, EventRequest


logger = logging.getLogger('zentral.contrib.mdm.events.management')


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

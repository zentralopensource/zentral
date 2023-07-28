import logging
from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent, EventMetadata, EventRequest


logger = logging.getLogger('zentral.contrib.mdm.events.management')


class ViewFileVaultPRKEvent(BaseEvent):
    event_type = "view_filevault_prk"
    tags = ["mdm"]


register_event_type(ViewFileVaultPRKEvent)


def post_view_filevault_prk_event(request, enrolled_device):
    event_metadata = EventMetadata(
        machine_serial_number=enrolled_device.serial_number,
        request=EventRequest.build_from_request(request),
    )
    event = ViewFileVaultPRKEvent(event_metadata, {})
    event.post()

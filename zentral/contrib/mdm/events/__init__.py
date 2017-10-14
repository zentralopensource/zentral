import logging
from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent

logger = logging.getLogger('zentral.contrib.mdm.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "mdm"}


class OTAEnrollmentRequestEvent(BaseEvent):
    event_type = "ota_enrollment_request"
    tags = ["mdm", "heartbeat"]


register_event_type(OTAEnrollmentRequestEvent)


class MDMRequestEvent(BaseEvent):
    event_type = "mdm_request"
    tags = ["mdm", "heartbeat"]


register_event_type(MDMRequestEvent)

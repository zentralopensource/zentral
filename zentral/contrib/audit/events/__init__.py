import logging
from zentral.core.events.base import BaseEvent, register_event_type

logger = logging.getLogger('zentral.contrib.audit.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "audit"}


class AuditEvent(BaseEvent):
    event_type = "audit"
    tags = ["audit"]
    payload_aggregations = [
        ("event_id", {"type": "terms", "bucket_number": 10, "label": "Event IDs"}),
    ]


register_event_type(AuditEvent)

import logging
from zentral.core.events.base import BaseEvent, register_event_type

logger = logging.getLogger('zentral.contrib.xnumon.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "xnumon"}


class XnumonLogEvent(BaseEvent):
    event_type = "xnumon_log"
    tags = ["xnumon"]


register_event_type(XnumonLogEvent)

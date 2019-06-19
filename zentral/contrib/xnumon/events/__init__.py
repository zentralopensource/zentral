import logging
from zentral.core.events.base import BaseEvent, register_event_type

logger = logging.getLogger('zentral.contrib.xnumon.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "xnumon"}


class XnumonOpsEvent(BaseEvent):
    event_type = "xnumon_ops"
    tags = ["xnumon"]
    xnumon_eventcode = 0


register_event_type(XnumonOpsEvent)


class XnumonStatsEvent(BaseEvent):
    event_type = "xnumon_stats"
    tags = ["xnumon"]
    xnumon_eventcode = 1


register_event_type(XnumonStatsEvent)


class XnumonImageExecEvent(BaseEvent):
    event_type = "xnumon_image_exec"
    tags = ["xnumon"]
    xnumon_eventcode = 2
    payload_aggregations = [
        ("image.signature", {"type": "terms", "bucket_number": 2, "label": "Signatures"}),
        ("paths", {"type": "table", "bucket_number": 50, "label": "Top 50. paths", "top": True,
                   "columns": [("image.path", "path")]}),
        ("certs", {"type": "table", "bucket_number": 50, "label": "Top 50. certs", "top": True,
                   "columns": [("image.certcn", "CN")]}),
    ]


register_event_type(XnumonImageExecEvent)


class XnumonProcessAccessEvent(BaseEvent):
    event_type = "xnumon_process_access"
    tags = ["xnumon"]
    xnumon_eventcode = 3


register_event_type(XnumonProcessAccessEvent)


class XnumonLaunchdAddEvent(BaseEvent):
    event_type = "xnumon_launchd_add"
    tags = ["xnumon"]
    xnumon_eventcode = 4


register_event_type(XnumonLaunchdAddEvent)

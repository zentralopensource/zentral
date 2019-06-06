import logging
from zentral.core.events.base import BaseEvent, register_event_type

logger = logging.getLogger('zentral.contrib.xnumon.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "xnumon"}


class XnumonOpsEvent(BaseEvent):
    event_type = "xnumon_ops"
    tags = ["xnumon"]
    xnumon_eventcode = 0


register_event_type(XnumonOpsEvent)


class XnumonImageExecEvent(BaseEvent):
    event_type = "xnumon_image_exec"
    tags = ["xnumon"]
    xnumon_eventcode = 2


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

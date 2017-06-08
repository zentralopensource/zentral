import logging
from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent
from zentral.core.queues import queues

logger = logging.getLogger('zentral.contrib.puppet.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "puppet"}


class PuppetReportEvent(BaseEvent):
    event_type = "puppet_report"
    tags = ["puppet"]


register_event_type(PuppetReportEvent)


def post_puppet_report(instance, user_agent, ip, report):
    raw_event = {"request": {"user_agent": user_agent,
                             "ip": ip},
                 "event_type": PuppetReportEvent.event_type,
                 "puppet_instance": instance,
                 "puppet_report": report}
    queues.post_raw_event("puppet_reports", raw_event)

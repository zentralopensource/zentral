import logging
from zentral.core.events.base import BaseEvent, register_event_type

logger = logging.getLogger('zentral.contrib.filebeat.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "filebeat"}


class FilebeatEnrollmentEvent(BaseEvent):
    event_type = "filebeat_enrollment"
    tags = ["filebeat"]


register_event_type(FilebeatEnrollmentEvent)


def post_enrollment_event(msn, user_agent, ip, data):
    FilebeatEnrollmentEvent.post_machine_request_payloads(msn, user_agent, ip, [data])

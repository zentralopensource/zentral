from datetime import datetime
import logging
from zentral.core.events.base import BaseEvent, register_event_type

logger = logging.getLogger('zentral.contrib.jamf_protect.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "jamf_protect"}


class JamfProtectEnrollmentEvent(BaseEvent):
    event_type = "jamf_protect_enrollment"
    tags = ["jamf_protect"]


register_event_type(JamfProtectEnrollmentEvent)


class JamfProtectEvent(BaseEvent):
    event_type = "jamf_protect_event"
    tags = ["jamf_protect"]
    payload_aggregations = [
        ("eventType", {"type": "terms", "bucket_number": 10, "label": "Event types"}),
    ]


register_event_type(JamfProtectEvent)


def get_event_created_at(event):
    return datetime.utcfromtimestamp(event["match"]["event"]["timestamp"])


def post_event(msn, user_agent, ip, data):
    data.pop("host", None)
    # remove duplicated information and actions
    match = data.get("match")
    if match:
        match.pop("actions", None)
        match.pop("tags", None)
        match.pop("context", None)
        for fact in match.get("facts", []):
            fact.pop("actions", None)
    JamfProtectEvent.post_machine_request_payloads(msn, user_agent, ip, [data], get_event_created_at)


def post_enrollment_event(msn, user_agent, ip, data):
    JamfProtectEnrollmentEvent.post_machine_request_payloads(msn, user_agent, ip, [data])

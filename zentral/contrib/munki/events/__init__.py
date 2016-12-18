import logging
from dateutil import parser
from zentral.core.events.base import BaseEvent, EventMetadata, EventRequest, register_event_type

logger = logging.getLogger('zentral.contrib.munki.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "munki"}


class MunkiRequestEvent(BaseEvent):
    event_type = "munki_request"
    tags = ["munki", "heartbeat"]


register_event_type(MunkiRequestEvent)


class MunkiEvent(BaseEvent):
    event_type = "munki_event"
    tags = ["munki"]


register_event_type(MunkiEvent)


def post_munki_request_event(msn, user_agent, ip, **kwargs):
    MunkiRequestEvent.post_machine_payloads(msn, user_agent, ip, [kwargs])


def post_munki_events(msn, user_agent, ip, data):
    for report in data:
        events = report.pop('events')
        metadata = EventMetadata(MunkiEvent.event_type,
                                 machine_serial_number=msn,
                                 request=EventRequest(user_agent, ip),
                                 tags=MunkiEvent.tags)
        for index, (created_at, payload) in enumerate(events):
            metadata.index = index
            metadata.created_at = parser.parse(created_at)
            payload.update(report)
            event = MunkiEvent(metadata, payload)
            event.post()

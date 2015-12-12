import logging
from dateutil import parser
from zentral.core.events import BaseEvent, EventMetadata, EventRequest, register_event_type

logger = logging.getLogger('zentral.contrib.munki.events')


class MunkiEvent(BaseEvent):
    event_type = "munki_event"

register_event_type(MunkiEvent)


def post_munki_events(msn, user_agent, ip, data):
    for report in data:
        events = report.pop('events')
        metadata = EventMetadata(MunkiEvent.event_type,
                                 machine_serial_number=msn,
                                 request=EventRequest(user_agent, ip))
        for index, (created_at, payload) in enumerate(events):
            metadata.index = index
            metadata.created_at = parser.parse(created_at)
            payload.update(report)
            event = MunkiEvent(metadata, payload)
            event.post()

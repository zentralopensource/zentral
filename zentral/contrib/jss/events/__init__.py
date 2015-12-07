import logging
from zentral.core.events import BaseEvent, EventMetadata, EventRequest, register_event_type

logger = logging.getLogger('zentral.contrib.jss.events')


class JSSEvent(BaseEvent):
    event_type = "jss_event"

register_event_type(JSSEvent)


def post_jss_event(msn, user_agent, ip, data):
    metadata = EventMetadata(JSSEvent.event_type,
                             machine_serial_number=msn,
                             request=EventRequest(user_agent, ip))
    event = JSSEvent(metadata, data)
    event.post()

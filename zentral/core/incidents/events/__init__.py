import logging
from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent

logger = logging.getLogger('zentral.contrib.incidents.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "incident"}


class IncidentEvent(BaseEvent):
    event_type = 'incident'
    tags = ["incident"]


register_event_type(IncidentEvent)


class MachineIncidentEvent(BaseEvent):
    event_type = 'machine_incident'
    tags = ["incident"]


register_event_type(MachineIncidentEvent)

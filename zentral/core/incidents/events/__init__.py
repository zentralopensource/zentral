import logging
import uuid
from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent, EventMetadata

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


def build_incident_events(incident_event_payloads, machine_serial_number=None, request=None):
    incident_events_uuid = uuid.uuid4()
    for incident_event_index, incident_event_payload in enumerate(incident_event_payloads):
        if "incident" in incident_event_payload:
            incident_event_cls = MachineIncidentEvent
        else:
            incident_event_cls = IncidentEvent
        incident_event_metadata = EventMetadata(
                event_type=incident_event_cls.event_type,
                tags=incident_event_cls.tags,
                uuid=incident_events_uuid,
                index=incident_event_index,
                machine_serial_number=machine_serial_number,
                request=request,
        )
        yield incident_event_cls(incident_event_metadata, incident_event_payload)

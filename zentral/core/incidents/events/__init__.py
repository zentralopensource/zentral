import logging
from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent


logger = logging.getLogger('zentral.contrib.incidents.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "incident"}


class BaseIncidentEvent(BaseEvent):
    namespace = 'incident'
    tags = ["incident"]

    def get_linked_objects_keys(self):
        keys = {}
        pk = self.payload.get("pk")
        if pk:
            keys["incident"] = [(pk,)]
        machine_incident_pk = self.payload.get("machine_incident", {}).get("pk")
        if machine_incident_pk:
            keys["machine_incident"] = [(machine_incident_pk,)]
        return keys


class IncidentCreatedEvent(BaseIncidentEvent):
    event_type = 'incident_created'


register_event_type(IncidentCreatedEvent)


class IncidentSeverityUpdatedEvent(BaseIncidentEvent):
    event_type = 'incident_severity_updated'


register_event_type(IncidentSeverityUpdatedEvent)


class IncidentStatusUpdatedEvent(BaseIncidentEvent):
    event_type = 'incident_status_updated'


register_event_type(IncidentStatusUpdatedEvent)


class MachineIncidentCreatedEvent(BaseIncidentEvent):
    event_type = 'machine_incident_created'


register_event_type(MachineIncidentCreatedEvent)


class MachineIncidentStatusUpdatedEvent(BaseIncidentEvent):
    event_type = 'machine_incident_status_updated'


register_event_type(MachineIncidentStatusUpdatedEvent)

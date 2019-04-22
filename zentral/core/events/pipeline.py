import logging
import uuid
from . import event_from_event_d
from .base import EventMetadata
from zentral.core.probes.conf import all_probes
from zentral.core.incidents.events import IncidentEvent, MachineIncidentEvent
from zentral.core.incidents.utils import update_or_create_open_incident, update_or_create_open_machine_incident

logger = logging.getLogger('zentral.core.events.pipeline')


def enrich_event(event):
    if isinstance(event, dict):
        event = event_from_event_d(event)
    for probe in all_probes.event_filtered(event):
        incident_severity = probe.get_matching_event_incident_severity(event)
        if incident_severity is None:
            continue
        if event.machine is not None:
            machine_incident, incident_event_payloads = update_or_create_open_machine_incident(
                probe.source,
                incident_severity,
                event.machine.serial_number,
                event.uuid
            )
            event.metadata.add_incident(machine_incident)
        else:
            incident, incident_event_payloads = update_or_create_open_incident(
                probe.source,
                incident_severity,
                event.uuid
            )
            event.metadata.add_incident(incident)
        incident_events_uuid = uuid.uuid4()
        for incident_event_index, incident_event_payload in enumerate(incident_event_payloads):
            if "machine_incident" in incident_event_payload:
                incident_event_cls = MachineIncidentEvent
            else:
                incident_event_cls = IncidentEvent
            incident_event_metadata = EventMetadata(
                    event_type=incident_event_cls.event_type,
                    tags=incident_event_cls.tags,
                    uuid=incident_events_uuid,
                    index=incident_event_index,
                    machine_serial_number=event.metadata.machine_serial_number,  # copied from original event
                    request=event.metadata.request  # copied from original event
            )
            yield incident_event_cls(incident_event_metadata, incident_event_payload)
    yield event


def process_event(event):
    if isinstance(event, dict):
        event = event_from_event_d(event)
    for probe in all_probes.event_filtered(event):
        for action, action_config_d in probe.actions:
            try:
                action.trigger(event, probe, action_config_d)
            except Exception:
                logger.exception("Could not trigger action %s", action.name)

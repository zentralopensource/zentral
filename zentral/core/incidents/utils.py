from datetime import datetime
import logging
import uuid
from django.db import IntegrityError, transaction
from zentral.core.events.base import EventMetadata, EventRequest
from .models import Incident, MachineIncident, Severity, Status
from .events import (IncidentCreatedEvent, IncidentSeverityUpdatedEvent, IncidentStatusUpdatedEvent,
                     MachineIncidentCreatedEvent, MachineIncidentStatusUpdatedEvent)


logger = logging.getLogger("zentral.core.incidents.utils")


def open_incident(incident_update):
    # get or update (severity) open incident
    event_cls = event_payload = None
    extra_event_payload = {}
    lookup = {"incident_type": incident_update.incident_type,
              "key": incident_update.key,
              "status__in": Status.open_values()}
    try:
        incident = Incident.objects.select_for_update().get(**lookup)
    except Incident.DoesNotExist:
        # create
        try:
            with transaction.atomic():
                incident = Incident.objects.create(
                    incident_type=incident_update.incident_type,
                    key=incident_update.key,
                    severity=incident_update.severity.value,
                    status=Status.OPEN.value,
                    status_time=datetime.utcnow()
                )
        except IntegrityError as e:
            # it was created in the meantime. fetch it
            try:
                incident = Incident.objects.select_for_update().get(**lookup)
            except Incident.DoesNotExist:
                # that should not happen
                logger.error("Incident type %s key %s: update or create race condition.",
                             incident_update.incident_type, incident_update.key)
                raise e
        else:
            event_cls = IncidentCreatedEvent
    if incident.severity < incident_update.severity.value:
        event_cls = IncidentSeverityUpdatedEvent
        extra_event_payload = {"previous_severity": incident.severity}
        incident.severity = incident_update.severity.value
        incident.save()
    if event_cls:
        event_payload = incident.serialize_for_event()
        event_payload.update(extra_event_payload)
        event_args = (event_cls, event_payload)
    else:
        event_args = None
    return incident, event_args


def close_open_incident(incident_update):
    assert(incident_update.severity == Severity.NONE)
    # close the incident if status == Status.OPEN
    # do not automatically close it if open but not Status.OPEN
    try:
        incident = Incident.objects.select_for_update().get(
            incident_type=incident_update.incident_type,
            key=incident_update.key,
            status=Status.OPEN.value
        )
    except Incident.DoesNotExist:
        # nothing to do
        return

    if incident.machineincident_set.filter(status__in=Status.open_values()).count():
        # other open machine incident in the incident, we cannot close it
        return

    # close found incident
    previous_status = {
        "status": incident.status,
        "status_time": incident.status_time
    }
    incident.status = Status.CLOSED.value
    incident.status_time = datetime.utcnow()
    incident.save()
    event_payload = incident.serialize_for_event()
    event_payload["previous_status"] = previous_status
    yield IncidentStatusUpdatedEvent, event_payload


def close_open_machine_incident(incident_update, serial_number):
    # close a machine incident if status == Status.OPEN
    # do not automatically close it if open but not status == status.OPEN (manual intervention)
    try:
        machine_incident = MachineIncident.objects.select_for_update().select_related("incident").get(
            incident__incident_type=incident_update.incident_type,
            incident__key=incident_update.key,
            serial_number=serial_number,
            status=Status.OPEN.value,
        )
    except MachineIncident.DoesNotExist:
        # nothing to do
        return

    # close found machine incident
    previous_status = {
        "status": machine_incident.status,
        "status_time": machine_incident.status_time
    }
    machine_incident.status = Status.CLOSED.value
    machine_incident.save()
    event_payload = machine_incident.serialize_for_event()
    event_payload["machine_incident"]["previous_status"] = previous_status
    yield (MachineIncidentStatusUpdatedEvent, event_payload)

    # close the incident if status == Status.OPEN
    # do not automatically close it if open but not status == Status.OPEN (manual intervention)
    incident = machine_incident.incident
    if incident.status not in Status.open_values():
        logger.error("Closed an open machine incident:%s on a closed incident:%s !!!",
                     machine_incident.pk, incident.pk)
    elif incident.status == Status.OPEN.value:
        if incident.machineincident_set.filter(status__in=Status.open_values()).count():
            # other open machine incident in the incident, we cannot close it
            return
        previous_status = {
            "status": incident.status,
            "status_time": incident.status_time
        }
        incident.status = Status.CLOSED.value
        incident.status_time = datetime.utcnow()
        incident.save()
        event_payload = incident.serialize_for_event()
        event_payload["previous_status"] = previous_status
        yield (IncidentStatusUpdatedEvent, event_payload)


def open_machine_incident(incident_update, serial_number):
    incident, event_args = open_incident(incident_update)
    if event_args:
        yield event_args
    machine_incident, created = MachineIncident.objects.get_or_create(
        incident=incident,
        serial_number=serial_number,
        status__in=Status.open_values(),
        defaults={"status": Status.OPEN.value,
                  "status_time": datetime.utcnow()}
    )
    if created:
        event_payload = machine_incident.serialize_for_event()
        yield (MachineIncidentCreatedEvent, event_payload)


def apply_incident_update(incident_update, serial_number):
    if incident_update.severity == Severity.NONE:
        if serial_number:
            yield from close_open_machine_incident(incident_update, serial_number)
        else:
            yield from close_open_incident(incident_update)
    else:
        if serial_number:
            yield from open_machine_incident(incident_update, serial_number)
        else:
            _, event_args = open_incident(incident_update)
            if event_args:
                yield event_args


def apply_incident_updates(original_event):
    events = []
    incident_updates = original_event.metadata.incident_updates
    if not incident_updates:
        return events
    serial_number = original_event.metadata.machine_serial_number
    event_uuid = uuid.uuid4()
    event_index = 0
    with transaction.atomic():
        for incident_update in incident_updates:
            for event_cls, event_payload in apply_incident_update(incident_update, serial_number):
                event_metadata = EventMetadata(
                    uuid=event_uuid,
                    index=event_index,
                    machine_serial_number=serial_number,
                    # copy the original event payload linked objects into the incident events metadata
                    objects=original_event.get_linked_objects_keys()
                )
                event = event_cls(event_metadata, event_payload)
                events.append(event)
                event_index += 1
                # copy the incident event payload linked objects into the original event metadata
                original_event.metadata.add_objects(event.get_linked_objects_keys())
    return events


def update_incident_status(incident, new_status, request):
    incident = Incident.objects.select_for_update().get(pk=incident.pk)
    if new_status not in incident.get_next_statuses():
        return incident, None
    previous_status = {"status": incident.status,
                       "status_time": incident.status_time}
    incident.status = new_status.value
    incident.status_time = datetime.utcnow()
    incident.save()

    # build event
    event_payload = incident.serialize_for_event()
    event_payload["previous_status"] = previous_status
    event = IncidentStatusUpdatedEvent(
        EventMetadata(request=EventRequest.build_from_request(request)),
        event_payload
    )

    return incident, event


def update_machine_incident_status(machine_incident, new_status, request):
    machine_incident = (MachineIncident.objects.select_for_update().select_related("incident")
                                               .get(pk=machine_incident.pk))
    if new_status not in machine_incident.get_next_statuses():
        return machine_incident, None
    previous_status = {"status": machine_incident.status,
                       "status_time": machine_incident.status_time}
    machine_incident.status = new_status.value
    machine_incident.status_time = datetime.utcnow()
    machine_incident.save()

    # build event
    event_payload = machine_incident.serialize_for_event()
    event_payload["machine_incident"]["previous_status"] = previous_status
    event = MachineIncidentStatusUpdatedEvent(
        EventMetadata(request=EventRequest.build_from_request(request)),
        event_payload
    )

    return machine_incident, event

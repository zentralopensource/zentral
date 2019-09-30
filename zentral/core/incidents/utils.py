import logging
from django.db import connection, IntegrityError, transaction
from prometheus_client import CollectorRegistry, Gauge
from .models import (Incident, MachineIncident,
                     OPEN_STATUSES, SEVERITY_CHOICES_DICT,
                     STATUS_CLOSED, STATUS_CHOICES_DICT, STATUS_OPEN)


logger = logging.getLogger("zentral.core.incidents.utils")


def _update_or_create_open_incident(probe_source, severity, event_id):
    action = event_payload = None
    extra_event_payload = {}
    lookup = {"probe_source": probe_source, "status__in": OPEN_STATUSES}
    try:
        incident = Incident.objects.select_for_update().get(**lookup)
    except Incident.DoesNotExist:
        try:
            with transaction.atomic():
                incident = Incident.objects.create(
                    probe_source=probe_source,
                    name=probe_source.name,
                    description=probe_source.description,
                    severity=severity,
                    status=STATUS_OPEN,
                    event_id=event_id)
        except IntegrityError as e:
            try:
                incident = Incident.objects.select_for_update().get(**lookup)
            except Incident.DoesNotExist:
                pass
            raise e
        else:
            action = "created"
    if incident.severity < severity:
        action = "updated"
        extra_event_payload = {"diff": {"removed": {"severity": incident.severity},
                                        "added": {"severity": severity}}}
        incident.severity = severity
        incident.save()
    if action is not None:
        event_payload = incident.serialize_for_event()
        event_payload["action"] = action
        event_payload.update(extra_event_payload)
    return incident, event_payload


def update_or_create_open_incident(probe_source, severity, event_id):
    event_payloads = []
    with transaction.atomic():
        incident, incident_event_payload = _update_or_create_open_incident(probe_source, severity, event_id)
    if incident_event_payload:
        event_payloads.append(incident_event_payload)
    return incident, event_payloads


def update_or_create_open_machine_incident(probe_source, severity, serial_number, event_id):
    event_payloads = []
    if severity == 0:
        # close a machine incident if status == "OPEN"
        # do not automatically close it if open but not status == "OPEN" (manual intervention)
        machine_incident = None
        with transaction.atomic():
            try:
                machine_incident = MachineIncident.objects.select_for_update().select_related("incident").get(
                    incident__probe_source=probe_source,
                    serial_number=serial_number,
                    status=STATUS_OPEN
                )
            except MachineIncident.DoesNotExist:
                pass
            else:
                machine_incident_diff = {"removed": {"status": machine_incident.status},
                                         "added": {"status": STATUS_CLOSED}}
                machine_incident.status = STATUS_CLOSED
                machine_incident.save()
                machine_incident_event_payload = machine_incident.serialize_for_event()
                machine_incident_event_payload["action"] = "closed"
                machine_incident_event_payload["diff"] = machine_incident_diff
                event_payloads.append(machine_incident_event_payload)
                # close the incident if status == "OPEN"
                # do not automatically close it if open but not status == "OPEN" (manual intervention)
                incident = machine_incident.incident
                if incident.status not in OPEN_STATUSES:
                    logger.error("Closed an open machine incident:%s on a closed incident:%s !!!",
                                 machine_incident.pk, incident.pk)
                elif incident.status == STATUS_OPEN:
                    # in that case, and only in that case, we can automatically close the incident
                    if incident.machineincident_set.filter(status__in=OPEN_STATUSES).count() == 0:
                        incident.status = STATUS_CLOSED
                        incident.save()
                        incident_event_payload = incident.serialize_for_event()
                        incident_event_payload["action"] = "closed"
                        incident_event_payload["diff"] = {"removed": {"status": STATUS_OPEN},
                                                          "added": {"status": STATUS_CLOSED}}
                        event_payloads.append(incident_event_payload)
    else:
        with transaction.atomic():
            incident, incident_event_payload = _update_or_create_open_incident(probe_source, severity, event_id)
            if incident_event_payload:
                event_payloads.append(incident_event_payload)
            machine_incident, created = MachineIncident.objects.get_or_create(
                incident=incident,
                serial_number=serial_number,
                status__in=OPEN_STATUSES,
                defaults={
                    "status": STATUS_OPEN,
                    "event_id": event_id,
                }
            )
            if created:
                machine_incident_event_payload = machine_incident.serialize_for_event()
                machine_incident_event_payload["action"] = "created"
                event_payloads.append(machine_incident_event_payload)
    return machine_incident, event_payloads


def update_incident_status(incident, new_status):
    event_payloads = []
    with transaction.atomic():
        try:
            incident = Incident.objects.select_for_update().get(pk=incident.pk)
        except Incident.DoesNotExist:
            return incident, event_payloads
        if new_status not in incident.get_next_statuses():
            return incident, event_payloads
        diff = {"removed": {"status": incident.status},
                "added": {"status": new_status}}
        incident.status = new_status
        incident.save()
        incident_event_payload = incident.serialize_for_event()
        incident_event_payload["action"] = "updated"
        incident_event_payload["diff"] = diff
        event_payloads.append(incident_event_payload)
    return incident, event_payloads


def update_machine_incident_status(machine_incident, new_status):
    event_payloads = []
    with transaction.atomic():
        try:
            machine_incident = (MachineIncident.objects.select_for_update().select_related("incident")
                                                       .get(pk=machine_incident.pk))
        except MachineIncident.DoesNotExist:
            return machine_incident, event_payloads
        if new_status not in machine_incident.get_next_statuses():
            return machine_incident, event_payloads
        diff = {"removed": {"status": machine_incident.status},
                "added": {"status": new_status}}
        machine_incident.status = new_status
        machine_incident.save()
        machine_incident_event_payload = machine_incident.serialize_for_event()
        machine_incident_event_payload["action"] = "updated"
        machine_incident_event_payload["diff"] = diff
        event_payloads.append(machine_incident_event_payload)
    return machine_incident, event_payloads


def get_prometheus_incidents_metrics():
    registry = CollectorRegistry()
    g = Gauge('zentral_incidents_count', 'Zentral incidents',
              ['name', 'id', 'severity', 'status', 'opened'],
              registry=registry)
    query = (
        "select count(*), "
        "i.id, i.name, i.severity, "
        "mi.status, (CASE WHEN mi.status in ('CLOSED', 'RESOLVED') THEN FALSE ELSE TRUE END) as opened "
        "from incidents_incident as i "
        "join incidents_machineincident as mi on (mi.incident_id = i.id) "
        "group by i.name, i.id, i.severity, mi.status, opened "
        "order by i.id, mi.status;"
    )
    cursor = connection.cursor()
    cursor.execute(query)
    columns = [col[0] for col in cursor.description]
    for row in cursor.fetchall():
        d = dict(zip(columns, row))
        d["severity"] = str(SEVERITY_CHOICES_DICT.get(d.pop("severity"), "Unknown"))
        d["status"] = str(STATUS_CHOICES_DICT.get(d.pop("status"), "Unknown"))
        d["opened"] = 'Y' if d["opened"] else 'N'
        count = d.pop('count')
        g.labels(**d).set(count)
    return registry

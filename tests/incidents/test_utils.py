from datetime import datetime
from django.http import HttpRequest
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.core.events.base import BaseEvent, EventMetadata
from zentral.core.incidents.events import (IncidentCreatedEvent, IncidentSeverityUpdatedEvent,
                                           IncidentStatusUpdatedEvent, MachineIncidentCreatedEvent,
                                           MachineIncidentStatusUpdatedEvent)
from zentral.core.incidents.models import Incident, IncidentUpdate, MachineIncident, Severity, Status
from zentral.core.incidents.utils import apply_incident_updates, update_incident_status, update_machine_incident_status


class TestEvent(BaseEvent):
    event_type = "test_event"

    def get_linked_objects_keys(self):
        return {"yolo": [(17,)]}


class IncidentTestCase(TestCase):
    def _create_event(self, severity=Severity.CRITICAL, serial_number=None):
        incident_type = get_random_string(12)
        key = {"key": get_random_string(12)}
        incident_update = IncidentUpdate(incident_type, key, severity)
        return TestEvent(
            EventMetadata(
                machine_serial_number=serial_number,
                incident_updates=[incident_update],
            ), {}
        ), incident_type, key

    def test_open_incident_no_existing_incident_create(self):
        # no existing incident, create one, return one IncidentCreatedEvent
        original_event, incident_type, key = self._create_event()
        events = apply_incident_updates(original_event)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, IncidentCreatedEvent)
        incident = Incident.objects.get(pk=event.payload["pk"])
        self.assertEqual(
            event.metadata.objects,
            {"yolo": [(17,)],  # copied from the original event
             "incident": [(incident.pk,)]}
        )
        self.assertEqual(
            original_event.metadata.objects,
            {"yolo": [(17,)],
             "incident": [(incident.pk,)]}  # copied from the incident event
        )
        self.assertEqual(incident.incident_type, incident_type)
        self.assertEqual(incident.key, key)
        self.assertEqual(incident.severity, Severity.CRITICAL.value)

    def test_open_incident_existing_open_incident_greater_severity_noop(self):
        # existing open incident, with greater Severity, noop
        original_event, incident_type, key = self._create_event(severity=Severity.MAJOR)
        existing_incident = Incident.objects.create(
            incident_type=incident_type,
            key=key,
            status=Status.OPEN.value,
            status_time=datetime.utcnow(),
            severity=Severity.CRITICAL.value
        )
        events = apply_incident_updates(original_event)
        self.assertEqual(len(events), 0)
        existing_incident.refresh_from_db()
        self.assertEqual(existing_incident.status, Status.OPEN.value)
        self.assertEqual(existing_incident.severity, Severity.CRITICAL.value)

    def test_open_incident_existing_open_incident_lower_severity_update(self):
        # existing open incident, with lower Severity, return one IncidentSeverityUpdatedEvent
        original_event, incident_type, key = self._create_event(severity=Severity.CRITICAL)
        existing_incident = Incident.objects.create(
            incident_type=incident_type,
            key=key,
            status=Status.OPEN.value,
            status_time=datetime.utcnow(),
            severity=Severity.MAJOR.value
        )
        events = apply_incident_updates(original_event)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, IncidentSeverityUpdatedEvent)
        self.assertEqual(
            event.metadata.objects,
            {"yolo": [(17,)],  # copied from the original event
             "incident": [(existing_incident.pk,)]}
        )
        self.assertEqual(
            original_event.metadata.objects,
            {"yolo": [(17,)],
             "incident": [(existing_incident.pk,)]}  # copied from the incident event
        )
        self.assertEqual(event.payload["pk"], existing_incident.pk)
        self.assertEqual(event.payload["severity"], Severity.CRITICAL.value)
        self.assertEqual(event.payload["previous_severity"], Severity.MAJOR.value)
        existing_incident.refresh_from_db()
        self.assertEqual(existing_incident.severity, Severity.CRITICAL.value)

    def test_close_open_incident_no_existing_incident_noop(self):
        # no existing incident, noop
        original_event, incident_type, key = self._create_event(severity=Severity.NONE)
        events = apply_incident_updates(original_event)
        self.assertEqual(len(events), 0)
        self.assertEqual(Incident.objects.filter(incident_type=incident_type, key=key).count(), 0)

    def test_close_open_incident_existing_open_incident(self):
        # existing open incident, IncidentStatusUpdatedEvent
        original_event, incident_type, key = self._create_event(severity=Severity.NONE)
        existing_incident = Incident.objects.create(
            incident_type=incident_type,
            key=key,
            status=Status.OPEN.value,
            status_time=datetime.utcnow(),
            severity=Severity.MAJOR.value
        )
        events = apply_incident_updates(original_event)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, IncidentStatusUpdatedEvent)
        self.assertEqual(
            event.metadata.objects,
            {"yolo": [(17,)],  # copied from the original event
             "incident": [(existing_incident.pk,)]}
        )
        self.assertEqual(
            original_event.metadata.objects,
            {"yolo": [(17,)],
             "incident": [(existing_incident.pk,)]}  # copied from the incident event
        )
        self.assertEqual(event.payload["pk"], existing_incident.pk)
        self.assertEqual(event.payload["previous_status"]["status"], Status.OPEN.value)
        self.assertEqual(event.payload["status"], Status.CLOSED.value)
        existing_incident.refresh_from_db()
        self.assertEqual(existing_incident.status, Status.CLOSED.value)

    def test_close_open_incident_existing_in_progress_incident_noop(self):
        # existing in progress incident, noop
        original_event, incident_type, key = self._create_event(severity=Severity.NONE)
        existing_incident = Incident.objects.create(
            incident_type=incident_type,
            key=key,
            status=Status.IN_PROGRESS.value,
            status_time=datetime.utcnow(),
            severity=Severity.MAJOR.value
        )
        events = apply_incident_updates(original_event)
        self.assertEqual(len(events), 0)
        existing_incident.refresh_from_db()
        self.assertEqual(existing_incident.status, Status.IN_PROGRESS.value)

    def test_close_open_incident_existing_open_incident_and_machine_incident_noop(self):
        # existing open incident and machine incident, noop
        original_event, incident_type, key = self._create_event(severity=Severity.NONE)
        existing_incident = Incident.objects.create(
            incident_type=incident_type,
            key=key,
            status=Status.OPEN.value,
            status_time=datetime.utcnow(),
            severity=Severity.MAJOR.value
        )
        existing_machine_incident = MachineIncident.objects.create(
            incident=existing_incident,
            serial_number=get_random_string(12),
            status=Status.OPEN.value,
            status_time=datetime.utcnow()
        )
        events = apply_incident_updates(original_event)
        self.assertEqual(len(events), 0)
        existing_incident.refresh_from_db()
        self.assertEqual(existing_incident.status, Status.OPEN.value)
        existing_machine_incident.refresh_from_db()
        self.assertEqual(existing_machine_incident.status, Status.OPEN.value)

    def test_close_open_machine_incident_no_machine_incident_noop(self):
        # no existing machine incident, noop
        original_event, incident_type, key = self._create_event(severity=Severity.NONE, serial_number="87654321")
        existing_incident = Incident.objects.create(
            incident_type=incident_type,
            key=key,
            status=Status.OPEN.value,
            status_time=datetime.utcnow(),
            severity=Severity.MAJOR.value
        )
        existing_machine_incident = MachineIncident.objects.create(
            incident=existing_incident,
            serial_number="12345678",
            status=Status.OPEN.value,
            status_time=datetime.utcnow()
        )
        events = apply_incident_updates(original_event)
        self.assertEqual(len(events), 0)
        existing_incident.refresh_from_db()
        self.assertEqual(existing_incident.status, Status.OPEN.value)
        existing_machine_incident.refresh_from_db()
        self.assertEqual(existing_machine_incident.status, Status.OPEN.value)

    def test_close_open_machine_incident_and_parent(self):
        # existing machine incident, open incident without other machine incidents, two status updates
        original_event, incident_type, key = self._create_event(severity=Severity.NONE, serial_number="12345678")
        existing_incident = Incident.objects.create(
            incident_type=incident_type,
            key=key,
            status=Status.OPEN.value,
            status_time=datetime.utcnow(),
            severity=Severity.MAJOR.value
        )
        existing_machine_incident = MachineIncident.objects.create(
            incident=existing_incident,
            serial_number="12345678",
            status=Status.OPEN.value,
            status_time=datetime.utcnow()
        )
        events = apply_incident_updates(original_event)
        self.assertEqual(len(events), 2)

        machine_incident_event = events[0]
        self.assertIsInstance(machine_incident_event, MachineIncidentStatusUpdatedEvent)
        self.assertEqual(
            machine_incident_event.metadata.objects,
            {"yolo": [(17,)],  # copied from the original event
             "incident": [(existing_incident.pk,)],
             "machine_incident": [(existing_machine_incident.pk,)]}
        )
        self.assertEqual(machine_incident_event.payload["machine_incident"]["pk"], existing_machine_incident.pk)
        self.assertEqual(machine_incident_event.payload["machine_incident"]["status"], Status.CLOSED.value)
        self.assertEqual(machine_incident_event.payload["machine_incident"]["previous_status"]["status"],
                         Status.OPEN.value)
        existing_machine_incident.refresh_from_db()
        self.assertEqual(existing_machine_incident.status, Status.CLOSED.value)

        incident_event = events[1]
        self.assertIsInstance(incident_event, IncidentStatusUpdatedEvent)
        self.assertEqual(
            incident_event.metadata.objects,
            {"yolo": [(17,)],  # copied from the original event
             "incident": [(existing_incident.pk,)]}
        )
        self.assertEqual(incident_event.payload["pk"], existing_incident.pk)
        self.assertEqual(incident_event.payload["status"], Status.CLOSED.value)
        self.assertEqual(incident_event.payload["previous_status"]["status"], Status.OPEN.value)
        existing_incident.refresh_from_db()
        self.assertEqual(existing_incident.status, Status.CLOSED.value)

        self.assertEqual(
            original_event.metadata.objects,
            {"yolo": [(17,)],
             "incident": [(existing_incident.pk,)],
             "machine_incident": [(existing_machine_incident.pk,)]}
        )

    def test_close_open_machine_incident_not_parent(self):
        # existing machine incident, open incident with other machine incidents, one status updates
        original_event, incident_type, key = self._create_event(severity=Severity.NONE, serial_number="12345678")
        existing_incident = Incident.objects.create(
            incident_type=incident_type,
            key=key,
            status=Status.OPEN.value,
            status_time=datetime.utcnow(),
            severity=Severity.MAJOR.value
        )
        existing_machine_incident = MachineIncident.objects.create(
            incident=existing_incident,
            serial_number="12345678",
            status=Status.OPEN.value,
            status_time=datetime.utcnow()
        )
        existing_machine_incident2 = MachineIncident.objects.create(
            incident=existing_incident,
            serial_number="87654321",
            status=Status.OPEN.value,
            status_time=datetime.utcnow()
        )
        events = apply_incident_updates(original_event)
        self.assertEqual(len(events), 1)

        machine_incident_event = events[0]
        self.assertIsInstance(machine_incident_event, MachineIncidentStatusUpdatedEvent)
        self.assertEqual(
            machine_incident_event.metadata.objects,
            {"yolo": [(17,)],  # copied from the original event
             "incident": [(existing_incident.pk,)],
             "machine_incident": [(existing_machine_incident.pk,)]}
        )
        self.assertEqual(
            original_event.metadata.objects,
            {"yolo": [(17,)],
             "incident": [(existing_incident.pk,)],
             "machine_incident": [(existing_machine_incident.pk,)]}
        )
        self.assertEqual(machine_incident_event.payload["machine_incident"]["pk"], existing_machine_incident.pk)
        self.assertEqual(machine_incident_event.payload["machine_incident"]["status"], Status.CLOSED.value)
        self.assertEqual(machine_incident_event.payload["machine_incident"]["previous_status"]["status"],
                         Status.OPEN.value)
        existing_machine_incident.refresh_from_db()
        self.assertEqual(existing_machine_incident.status, Status.CLOSED.value)

        existing_incident.refresh_from_db()
        self.assertEqual(existing_incident.status, Status.OPEN.value)

        existing_machine_incident2.refresh_from_db()
        self.assertEqual(existing_machine_incident2.status, Status.OPEN.value)

    def test_open_machine_incident_noop(self):
        # incident and machine incident already exist, noop
        original_event, incident_type, key = self._create_event(serial_number="12345678")
        existing_incident = Incident.objects.create(
            incident_type=incident_type,
            key=key,
            status=Status.OPEN.value,
            status_time=datetime.utcnow(),
            severity=Severity.CRITICAL.value
        )
        MachineIncident.objects.create(
            incident=existing_incident,
            serial_number="12345678",
            status=Status.OPEN.value,
            status_time=datetime.utcnow()
        )
        events = apply_incident_updates(original_event)
        self.assertEqual(len(events), 0)
        self.assertEqual(Incident.objects.filter(incident_type=incident_type, key=key).count(), 1)
        self.assertEqual(MachineIncident.objects.filter(incident__incident_type=incident_type,
                                                        incident__key=key).count(), 1)

    def test_open_machine_incident_one_machine_incident_created_event(self):
        # incident already exist, no machine incident, one MachineIncidentCreatedEvent
        original_event, incident_type, key = self._create_event(serial_number="12345678")
        existing_incident = Incident.objects.create(
            incident_type=incident_type,
            key=key,
            status=Status.OPEN.value,
            status_time=datetime.utcnow(),
            severity=Severity.CRITICAL.value
        )
        MachineIncident.objects.create(
            incident=existing_incident,
            serial_number="87654321",
            status=Status.OPEN.value,
            status_time=datetime.utcnow()
        )
        events = apply_incident_updates(original_event)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, MachineIncidentCreatedEvent)
        machine_incident = MachineIncident.objects.get(incident__incident_type=incident_type,
                                                       incident__key=key,
                                                       serial_number="12345678")
        self.assertEqual(event.payload["machine_incident"]["pk"], machine_incident.pk)
        self.assertEqual(
            event.metadata.objects,
            {"yolo": [(17,)],  # copied from the original event
             "incident": [(existing_incident.pk,)],
             "machine_incident": [(machine_incident.pk,)]}
        )
        self.assertEqual(
            original_event.metadata.objects,
            {"yolo": [(17,)],
             "incident": [(existing_incident.pk,)],
             "machine_incident": [(machine_incident.pk,)]}
        )
        self.assertEqual(MachineIncident.objects.filter(incident__incident_type=incident_type,
                                                        incident__key=key).count(), 2)

    def test_open_machine_incident_one_incident_severity_updated_one_machine_incident_created(self):
        # incident already exist with different severity, no machine incident,
        # one IncidentSeverityUpdatedEvent, one MachineIncidentCreatedEvent
        original_event, incident_type, key = self._create_event(serial_number="12345678")
        existing_incident = Incident.objects.create(
            incident_type=incident_type,
            key=key,
            status=Status.OPEN.value,
            status_time=datetime.utcnow(),
            severity=Severity.MAJOR.value
        )
        MachineIncident.objects.create(
            incident=existing_incident,
            serial_number="87654321",
            status=Status.OPEN.value,
            status_time=datetime.utcnow()
        )
        events = apply_incident_updates(original_event)
        self.assertEqual(len(events), 2)

        incident_event = events[0]
        self.assertIsInstance(incident_event, IncidentSeverityUpdatedEvent)
        self.assertEqual(
            incident_event.metadata.objects,
            {"yolo": [(17,)],  # copied from the original event
             "incident": [(existing_incident.pk,)]}
        )
        self.assertEqual(incident_event.payload["previous_severity"], Severity.MAJOR.value)
        self.assertEqual(incident_event.payload["severity"], Severity.CRITICAL.value)
        existing_incident.refresh_from_db()
        self.assertEqual(existing_incident.severity, Severity.CRITICAL.value)

        machine_incident_event = events[1]
        self.assertIsInstance(machine_incident_event, MachineIncidentCreatedEvent)
        machine_incident = MachineIncident.objects.get(incident__incident_type=incident_type,
                                                       incident__key=key,
                                                       serial_number="12345678")
        self.assertEqual(machine_incident_event.payload["machine_incident"]["pk"],
                         machine_incident.pk)
        self.assertEqual(
            machine_incident_event.metadata.objects,
            {"yolo": [(17,)],  # copied from the original event
             "incident": [(existing_incident.pk,)],
             "machine_incident": [(machine_incident.pk,)]}
        )
        self.assertEqual(MachineIncident.objects.filter(incident__incident_type=incident_type,
                                                        incident__key=key).count(), 2)
        self.assertEqual(
            original_event.metadata.objects,
            {"yolo": [(17,)],
             "incident": [(existing_incident.pk,)],
             "machine_incident": [(machine_incident.pk,)]}
        )

    def test_open_incident_and_machine_incident(self):
        # incident already exist, with machine incident, but not open
        # one IncidentCreatedEvent, one MachineIncidentCreatedEvent
        original_event, incident_type, key = self._create_event(serial_number="12345678")
        existing_incident = Incident.objects.create(
            incident_type=incident_type,
            key=key,
            status=Status.CLOSED.value,
            status_time=datetime.utcnow(),
            severity=Severity.MAJOR.value
        )
        existing_machine_incident = MachineIncident.objects.create(
            incident=existing_incident,
            serial_number="12345678",
            status=Status.CLOSED.value,
            status_time=datetime.utcnow()
        )
        events = apply_incident_updates(original_event)
        self.assertEqual(len(events), 2)

        incident_event = events[0]
        self.assertIsInstance(incident_event, IncidentCreatedEvent)
        new_incident = Incident.objects.get(pk=incident_event.payload["pk"])
        self.assertEqual(
            incident_event.metadata.objects,
            {"yolo": [(17,)],  # copied from the original event
             "incident": [(new_incident.pk,)]}
        )
        self.assertEqual(new_incident.incident_type, incident_type)
        self.assertEqual(new_incident.key, key)
        self.assertEqual(new_incident.status, Status.OPEN.value)
        self.assertNotEqual(new_incident.pk, existing_incident.pk)
        existing_incident.refresh_from_db()
        self.assertEqual(existing_incident.status, Status.CLOSED.value)
        self.assertEqual(Incident.objects.filter(incident_type=incident_type, key=key).count(), 2)

        machine_incident_event = events[1]
        self.assertIsInstance(machine_incident_event, MachineIncidentCreatedEvent)
        new_machine_incident = MachineIncident.objects.get(incident__incident_type=incident_type,
                                                           incident__key=key,
                                                           status=Status.OPEN.value,
                                                           serial_number="12345678")
        self.assertEqual(
            machine_incident_event.metadata.objects,
            {"yolo": [(17,)],  # copied from the original event
             "incident": [(new_incident.pk,)],
             "machine_incident": [(new_machine_incident.pk,)]}
        )
        self.assertEqual(machine_incident_event.payload["machine_incident"]["pk"],
                         new_machine_incident.pk)
        existing_machine_incident.refresh_from_db()
        self.assertEqual(existing_machine_incident.status, Status.CLOSED.value)
        self.assertEqual(MachineIncident.objects.filter(incident__incident_type=incident_type,
                                                        incident__key=key).count(), 2)
        self.assertEqual(
            original_event.metadata.objects,
            {"yolo": [(17,)],
             "incident": [(new_incident.pk,)],
             "machine_incident": [(new_machine_incident.pk,)]}
        )

    def test_update_incident_status_noop(self):
        incident = Incident.objects.create(
            incident_type=get_random_string(12),
            key={"key": get_random_string(12)},
            status=Status.CLOSED.value,
            status_time=datetime.utcnow(),
            severity=Severity.MAJOR.value
        )
        request = HttpRequest()
        request.user = None
        updated_incident, event = update_incident_status(incident, Status.IN_PROGRESS, request)
        self.assertEqual(updated_incident, incident)
        self.assertEqual(updated_incident.status, Status.CLOSED.value)
        self.assertIsNone(event)

    def test_update_incident_status_ok(self):
        incident = Incident.objects.create(
            incident_type=get_random_string(12),
            key={"key": get_random_string(12)},
            status=Status.OPEN.value,
            status_time=datetime.utcnow(),
            severity=Severity.MAJOR.value
        )
        request = HttpRequest()
        request.user = None
        updated_incident, event = update_incident_status(incident, Status.IN_PROGRESS, request)
        self.assertEqual(updated_incident, incident)
        self.assertEqual(updated_incident.status, Status.IN_PROGRESS.value)
        self.assertIsInstance(event, IncidentStatusUpdatedEvent)
        self.assertEqual(event.payload["status"], Status.IN_PROGRESS.value)
        self.assertEqual(event.payload["previous_status"]["status"], Status.OPEN.value)
        self.assertEqual(
            event.metadata.objects,
            {"incident": [(incident.pk,)]}
        )

    def test_update_machine_incident_status_noop(self):
        incident = Incident.objects.create(
            incident_type=get_random_string(12),
            key={"key": get_random_string(12)},
            status=Status.CLOSED.value,
            status_time=datetime.utcnow(),
            severity=Severity.MAJOR.value
        )
        machine_incident = MachineIncident.objects.create(
            incident=incident,
            serial_number="12345678",
            status=Status.CLOSED.value,
            status_time=datetime.utcnow(),
        )
        request = HttpRequest()
        request.user = None
        updated_machine_incident, event = update_machine_incident_status(
            machine_incident, Status.IN_PROGRESS, request
        )
        self.assertEqual(updated_machine_incident, machine_incident)
        self.assertEqual(updated_machine_incident.status, Status.CLOSED.value)
        self.assertIsNone(event)

    def test_update_machine_incident_status_ok(self):
        incident = Incident.objects.create(
            incident_type=get_random_string(12),
            key={"key": get_random_string(12)},
            status=Status.OPEN.value,
            status_time=datetime.utcnow(),
            severity=Severity.MAJOR.value
        )
        machine_incident = MachineIncident.objects.create(
            incident=incident,
            serial_number="12345678",
            status=Status.OPEN.value,
            status_time=datetime.utcnow(),
        )
        request = HttpRequest()
        request.user = None
        updated_machine_incident, event = update_machine_incident_status(
            machine_incident, Status.IN_PROGRESS, request
        )
        self.assertEqual(updated_machine_incident, machine_incident)
        self.assertEqual(updated_machine_incident.status, Status.IN_PROGRESS.value)
        self.assertIsInstance(event, MachineIncidentStatusUpdatedEvent)
        self.assertEqual(event.payload["machine_incident"]["status"], Status.IN_PROGRESS.value)
        self.assertEqual(event.payload["machine_incident"]["previous_status"]["status"], Status.OPEN.value)
        self.assertEqual(
            event.metadata.objects,
            {"incident": [(incident.pk,)],
             "machine_incident": [(machine_incident.pk,)]}
        )

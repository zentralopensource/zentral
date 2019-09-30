from django.test import TestCase
from zentral.contrib.inventory.models import MetaBusinessUnit, Tag
from zentral.core.events.base import BaseEvent, EventMetadata
from zentral.core.events.pipeline import enrich_event
from zentral.core.incidents.events import IncidentEvent, MachineIncidentEvent
from zentral.core.incidents.models import (Incident, MachineIncident,
                                           SEVERITY_CRITICAL,
                                           STATUS_CLOSED, STATUS_IN_PROGRESS, STATUS_OPEN)
from zentral.core.incidents.utils import update_or_create_open_incident, update_or_create_open_machine_incident
from zentral.contrib.inventory.models import MetaMachine
from zentral.core.probes.models import ProbeSource
from tests.inventory.utils import MockMetaMachine


class IncidentTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # test probe
        cls.mbu1 = MetaBusinessUnit.objects.create(name="MBU1")
        cls.tag1 = Tag.objects.create(name="TAG1")
        cls.probe_source = ProbeSource.objects.create(
            model="BaseProbe",
            name="base probe",
            status=ProbeSource.ACTIVE,
            body={"incident_severity": SEVERITY_CRITICAL,
                  "filters": {
                      "metadata": [{"event_types": ["test"]}]
                  }}
        )
        cls.probe = cls.probe_source.load()

    def test_create_open_incident(self):
        event_metadata = EventMetadata(event_type="test")
        event = BaseEvent(event_metadata, {"joe": "jackson"})
        self.assertTrue(self.probe.test_event(event))
        self.assertEqual(self.probe.get_matching_event_incident_severity(event), SEVERITY_CRITICAL)
        incident, event_payloads = update_or_create_open_incident(self.probe_source,
                                                                  SEVERITY_CRITICAL,
                                                                  event.metadata.uuid)
        # incident
        self.assertEqual(incident.probe_source, self.probe_source)
        self.assertEqual(incident.name, "base probe")
        self.assertEqual(incident.status, STATUS_OPEN)
        self.assertEqual(incident.severity, SEVERITY_CRITICAL)
        self.assertEqual(incident.event_id, event.metadata.uuid)
        self.assertEqual(MachineIncident.objects.count(), 0)
        self.assertEqual([incident], list(Incident.objects.all()))
        # event payload
        self.assertEqual(len(event_payloads), 1)
        event_payload = event_payloads[0]
        self.assertEqual(event_payload["action"], "created")
        self.assertEqual(event_payload["pk"], incident.pk)
        self.assertEqual(event_payload["probe_pk"], self.probe_source.pk)
        self.assertEqual(event_payload["name"], "base probe")
        self.assertEqual(event_payload["status"], STATUS_OPEN)
        self.assertEqual(event_payload["severity"], SEVERITY_CRITICAL)
        self.assertEqual(event_payload["event_id"], str(event.metadata.uuid))
        self.assertEqual(event_payload.get("incident"), None)  # not a machine incident payload

    def test_same_open_incident(self):
        event1_metadata = EventMetadata(event_type="test")
        event1 = BaseEvent(event1_metadata, {"joe": "jackson"})
        self.assertTrue(self.probe.test_event(event1))
        incident, _ = update_or_create_open_incident(self.probe_source,
                                                     SEVERITY_CRITICAL,
                                                     event1.metadata.uuid)
        event2_metadata = EventMetadata(event_type="test")
        event2 = BaseEvent(event2_metadata, {"joe": "jackson"})
        self.assertTrue(self.probe.test_event(event2))
        incident2, event_payloads = update_or_create_open_incident(self.probe_source,
                                                                   SEVERITY_CRITICAL,
                                                                   event2.metadata.uuid)
        self.assertEqual(incident, incident2)
        self.assertEqual(len(event_payloads), 0)

    def test_update_open_incident(self):
        event_metadata = EventMetadata(event_type="test")
        event = BaseEvent(event_metadata, {"joe": "jackson"})
        self.assertTrue(self.probe.test_event(event))
        incident, _ = update_or_create_open_incident(self.probe_source,
                                                     SEVERITY_CRITICAL,
                                                     event.metadata.uuid)
        incident2, event_payloads = update_or_create_open_incident(self.probe_source,
                                                                   SEVERITY_CRITICAL + 100,
                                                                   event.metadata.uuid)
        self.assertEqual(incident, incident2)
        self.assertEqual(incident2.severity, SEVERITY_CRITICAL + 100)
        self.assertEqual(Incident.objects.all().count(), 1)
        self.assertEqual(len(event_payloads), 1)
        event_payload = event_payloads[0]
        self.assertEqual(event_payload["action"], "updated")
        self.assertEqual(event_payload["diff"],
                         {"removed": {"severity": SEVERITY_CRITICAL},
                          "added": {"severity": SEVERITY_CRITICAL + 100}})
        self.assertEqual(event_payload["severity"], SEVERITY_CRITICAL + 100)

    def test_create_open_machine_incident(self):
        event_metadata = EventMetadata(event_type="test", machine_serial_number="YOLOFOMO")
        event_metadata.machine = MockMetaMachine([self.mbu1], [self.tag1],
                                                 "WINDOWS", "LAPTOP",
                                                 serial_number="YOLOFOMO")
        event = BaseEvent(event_metadata, {"joe": "jackson"})
        self.assertTrue(self.probe.test_event(event))
        machine_incident, event_payloads = update_or_create_open_machine_incident(
            self.probe_source,
            self.probe.get_matching_event_incident_severity(event),
            event.metadata.machine_serial_number,
            event.metadata.uuid
        )
        # machine incident
        self.assertEqual([machine_incident], list(MachineIncident.objects.all()))
        self.assertEqual(machine_incident.status, STATUS_OPEN)
        self.assertEqual(machine_incident.event_id, event.metadata.uuid)
        # incident
        incident = machine_incident.incident
        self.assertEqual([incident], list(Incident.objects.all()))
        self.assertEqual(incident.probe_source, self.probe_source)
        self.assertEqual(incident.name, "base probe")
        self.assertEqual(incident.status, STATUS_OPEN)
        self.assertEqual(incident.severity, SEVERITY_CRITICAL)
        self.assertEqual(incident.event_id, event.metadata.uuid)
        # event payloads
        self.assertEqual(len(event_payloads), 2)
        event_payload1, event_payload2 = event_payloads
        # incident event payload
        self.assertEqual(event_payload1["action"], "created")
        self.assertEqual(event_payload1["pk"], incident.pk)
        self.assertEqual(event_payload1.get("incident"), None)
        # machine incident event payload
        self.assertEqual(event_payload2["action"], "created")
        self.assertEqual(event_payload2["pk"], machine_incident.pk)
        self.assertEqual(event_payload2["status"], machine_incident.status)
        self.assertEqual(event_payload2["event_id"], str(event.metadata.uuid))
        self.assertEqual(event_payload2["incident"]["pk"], incident.pk)
        # meta machine
        self.assertEqual(MetaMachine("YOLOFOMO").max_incident_severity(), SEVERITY_CRITICAL)

    def test_same_open_machine_incident(self):
        event_metadata = EventMetadata(event_type="test", machine_serial_number="YOLOFOMO")
        event_metadata.machine = MockMetaMachine([self.mbu1], [self.tag1],
                                                 "WINDOWS", "LAPTOP",
                                                 serial_number="YOLOFOMO")
        event = BaseEvent(event_metadata, {"joe": "jackson"})
        self.assertTrue(self.probe.test_event(event))
        machine_incident1, _ = update_or_create_open_machine_incident(
            self.probe_source,
            self.probe.get_matching_event_incident_severity(event),
            event.metadata.machine_serial_number,
            event.metadata.uuid
        )
        machine_incident2, event_payloads = update_or_create_open_machine_incident(
            self.probe_source,
            self.probe.get_matching_event_incident_severity(event),
            event.metadata.machine_serial_number,
            event.metadata.uuid
        )
        self.assertEqual(machine_incident1, machine_incident2)
        self.assertEqual(len(event_payloads), 0)

    def test_update_open_machine_incident(self):
        event_metadata = EventMetadata(event_type="test", machine_serial_number="YOLOFOMO")
        event_metadata.machine = MockMetaMachine([self.mbu1], [self.tag1],
                                                 "WINDOWS", "LAPTOP",
                                                 serial_number="YOLOFOMO")
        event = BaseEvent(event_metadata, {"joe": "jackson"})
        self.assertTrue(self.probe.test_event(event))
        machine_incident1, _ = update_or_create_open_machine_incident(
            self.probe_source,
            self.probe.get_matching_event_incident_severity(event),
            event.metadata.machine_serial_number,
            event.metadata.uuid
        )
        machine_incident2, event_payloads = update_or_create_open_machine_incident(
            self.probe_source,
            self.probe.get_matching_event_incident_severity(event) + 100,
            event.metadata.machine_serial_number,
            event.metadata.uuid
        )
        self.assertEqual(machine_incident1, machine_incident2)
        self.assertEqual(machine_incident2.incident, machine_incident1.incident)
        self.assertEqual(machine_incident2.incident.severity, SEVERITY_CRITICAL + 100)
        self.assertEqual(len(event_payloads), 1)
        event_payload = event_payloads[0]
        self.assertEqual(event_payload["action"], "updated")
        self.assertEqual(event_payload["diff"],
                         {"removed": {"severity": SEVERITY_CRITICAL},
                          "added": {"severity": SEVERITY_CRITICAL + 100}})
        self.assertEqual(event_payload["severity"], SEVERITY_CRITICAL + 100)
        self.assertEqual(event_payload.get("incident"), None)
        # meta machine
        self.assertEqual(MetaMachine("YOLOFOMO").max_incident_severity(), SEVERITY_CRITICAL + 100)

    def test_close_open_machine_incident(self):
        event_metadata = EventMetadata(event_type="test", machine_serial_number="YOLOFOMO")
        event_metadata.machine = MockMetaMachine([self.mbu1], [self.tag1],
                                                 "WINDOWS", "LAPTOP",
                                                 serial_number="YOLOFOMO")
        event = BaseEvent(event_metadata, {"joe": "jackson"})
        self.assertTrue(self.probe.test_event(event))
        machine_incident1, _ = update_or_create_open_machine_incident(
            self.probe_source,
            self.probe.get_matching_event_incident_severity(event),
            event.metadata.machine_serial_number,
            event.metadata.uuid
        )
        self.assertEqual(machine_incident1.status, STATUS_OPEN)
        self.assertEqual(machine_incident1.incident.status, STATUS_OPEN)
        machine_incident2, event_payloads = update_or_create_open_machine_incident(
            self.probe_source,
            0,  # severity == 0 => close
            event.metadata.machine_serial_number,
            event.metadata.uuid
        )
        self.assertEqual(machine_incident1, machine_incident2)
        self.assertEqual(machine_incident2.incident, machine_incident1.incident)
        self.assertEqual(machine_incident2.status, STATUS_CLOSED)
        incident = machine_incident2.incident
        self.assertEqual(incident.severity, SEVERITY_CRITICAL)
        self.assertEqual(incident.status, STATUS_CLOSED)
        self.assertEqual(len(event_payloads), 2)
        event_payload1, event_payload2 = event_payloads
        # machine incident event payload
        self.assertEqual(event_payload1["action"], "closed")
        self.assertEqual(event_payload1["incident"]["pk"], incident.pk)
        self.assertEqual(event_payload1["incident"]["status"], STATUS_OPEN)  # Incident still open
        self.assertEqual(event_payload1["pk"], machine_incident2.pk)
        self.assertEqual(event_payload1["status"], machine_incident2.status)
        self.assertEqual(event_payload1["event_id"], str(event.metadata.uuid))
        self.assertEqual(event_payload1["diff"], {"removed": {"status": STATUS_OPEN},
                                                  "added": {"status": STATUS_CLOSED}})
        # incident event payload
        self.assertEqual(event_payload2["action"], "closed")
        self.assertEqual(event_payload2["pk"], incident.pk)
        self.assertEqual(event_payload2["status"], STATUS_CLOSED)  # Incident closed now
        self.assertEqual(event_payload2.get("incident"), None)
        self.assertEqual(event_payload2["diff"],
                         {"removed": {"status": STATUS_OPEN},
                          "added": {"status": STATUS_CLOSED}})
        # meta machine
        self.assertEqual(MetaMachine("YOLOFOMO").max_incident_severity(), None)

    def test_close_manually_changed_incident_open_machine_incident(self):
        event_metadata = EventMetadata(event_type="test", machine_serial_number="YOLOFOMO")
        event_metadata.machine = MockMetaMachine([self.mbu1], [self.tag1],
                                                 "WINDOWS", "LAPTOP",
                                                 serial_number="YOLOFOMO")
        event = BaseEvent(event_metadata, {"joe": "jackson"})
        self.assertTrue(self.probe.test_event(event))
        machine_incident1, _ = update_or_create_open_machine_incident(
            self.probe_source,
            self.probe.get_matching_event_incident_severity(event),
            event.metadata.machine_serial_number,
            event.metadata.uuid
        )
        # manually changed incident status
        incident = machine_incident1.incident
        incident.status = STATUS_IN_PROGRESS
        incident.save()
        machine_incident2, event_payloads = update_or_create_open_machine_incident(
            self.probe_source,
            0,  # severity == 0 => close
            event.metadata.machine_serial_number,
            event.metadata.uuid
        )
        self.assertEqual(machine_incident1, machine_incident2)
        self.assertEqual(machine_incident2.incident, machine_incident1.incident)
        self.assertEqual(machine_incident2.status, STATUS_CLOSED)
        self.assertEqual(incident.status, STATUS_IN_PROGRESS)  # not touched because manually changed
        self.assertEqual(len(event_payloads), 1)
        event_payload = event_payloads[0]
        self.assertEqual(event_payload["action"], "closed")
        self.assertEqual(event_payload["pk"], machine_incident2.pk)
        self.assertEqual(event_payload["status"], STATUS_CLOSED)  # machine incident closed
        self.assertEqual(event_payload["incident"]["pk"], incident.pk)
        self.assertEqual(event_payload["incident"]["status"], STATUS_IN_PROGRESS)  # incident still in progress

    def test_close_manually_changed_open_machine_incident(self):
        event_metadata = EventMetadata(event_type="test", machine_serial_number="YOLOFOMO")
        event_metadata.machine = MockMetaMachine([self.mbu1], [self.tag1],
                                                 "WINDOWS", "LAPTOP",
                                                 serial_number="YOLOFOMO")
        event = BaseEvent(event_metadata, {"joe": "jackson"})
        self.assertTrue(self.probe.test_event(event))
        machine_incident1, _ = update_or_create_open_machine_incident(
            self.probe_source,
            self.probe.get_matching_event_incident_severity(event),
            event.metadata.machine_serial_number,
            event.metadata.uuid
        )
        # manually changed incident status
        machine_incident1.status = STATUS_IN_PROGRESS
        machine_incident1.save()
        machine_incident2, event_payloads = update_or_create_open_machine_incident(
            self.probe_source,
            0,  # severity == 0 => close
            event.metadata.machine_serial_number,
            event.metadata.uuid
        )
        # no changes, because the machine incident was manually changed
        self.assertEqual(machine_incident2, None)
        self.assertEqual(len(event_payloads), 0)

    def test_close_one_of_two_open_machine_incident(self):
        event_metadata1 = EventMetadata(event_type="test", machine_serial_number="YOLOFOMO1")
        event_metadata1.machine = MockMetaMachine([self.mbu1], [self.tag1],
                                                  "WINDOWS", "LAPTOP",
                                                  serial_number="YOLOFOMO1")
        event1 = BaseEvent(event_metadata1, {"joe": "jackson"})
        self.assertTrue(self.probe.test_event(event1))
        machine_incident1, _ = update_or_create_open_machine_incident(
            self.probe_source,
            self.probe.get_matching_event_incident_severity(event1),
            event1.metadata.machine_serial_number,
            event1.metadata.uuid
        )
        event_metadata2 = EventMetadata(event_type="test", machine_serial_number="YOLOFOMO2")
        event_metadata2.machine = MockMetaMachine([self.mbu1], [self.tag1],
                                                  "WINDOWS", "LAPTOP",
                                                  serial_number="YOLOFOMO2")
        event2 = BaseEvent(event_metadata2, {"joe": "jackson"})
        self.assertTrue(self.probe.test_event(event2))
        machine_incident2, _ = update_or_create_open_machine_incident(
            self.probe_source,
            self.probe.get_matching_event_incident_severity(event2),
            event2.metadata.machine_serial_number,
            event2.metadata.uuid
        )
        # 2 machine incidents on 1 incident
        self.assertNotEqual(machine_incident1, machine_incident2)
        self.assertEqual(machine_incident1.serial_number, "YOLOFOMO1")
        self.assertEqual(machine_incident2.serial_number, "YOLOFOMO2")
        self.assertEqual(machine_incident1.incident, machine_incident2.incident)
        # close one machine incident
        machine_incident3, event_payloads = update_or_create_open_machine_incident(
            self.probe_source,
            0,
            event2.metadata.machine_serial_number,
            event2.metadata.uuid
        )
        self.assertEqual(machine_incident3, machine_incident2)
        self.assertEqual(machine_incident3.incident, machine_incident2.incident)
        incident = machine_incident3.incident
        self.assertEqual(incident.status, STATUS_OPEN)
        self.assertEqual(machine_incident3.status, STATUS_CLOSED)
        machine_incident1.refresh_from_db()
        self.assertEqual(machine_incident1.status, STATUS_OPEN)
        self.assertEqual(len(event_payloads), 1)
        event_payload = event_payloads[0]
        self.assertEqual(event_payload["action"], "closed")
        self.assertEqual(event_payload["pk"], machine_incident3.pk)
        self.assertEqual(event_payload["status"], STATUS_CLOSED)

    def test_enrich_event_no_match(self):
        event_metadata = EventMetadata(event_type="test2")
        event = BaseEvent(event_metadata, {"joe": "jackson"})
        self.assertFalse(self.probe.test_event(event))
        self.assertEqual([event], list(enrich_event(event)))

    def test_enrich_event_incident_match(self):
        event_metadata = EventMetadata(event_type="test")
        event = BaseEvent(event_metadata, {"joe": "jackson"})
        self.assertTrue(self.probe.test_event(event))
        enriched_events = list(enrich_event(event))
        self.assertEqual(len(enriched_events), 2)
        eevent1, eevent2 = enriched_events
        # first event is the incident event
        self.assertIsInstance(eevent1, IncidentEvent)
        self.assertEqual(eevent1.payload["action"], "created")
        incident = Incident.objects.all()[0]
        self.assertEqual(eevent1.payload["pk"], incident.pk)
        # incident in the original event metadata incidents
        self.assertEqual(len(eevent2.metadata.incidents), 1)
        eevent2_incident = eevent2.metadata.incidents[0]
        self.assertEqual(eevent2_incident["pk"], incident.pk)
        self.assertEqual(eevent2_incident.get("machine_incident"), None)
        # second event is the original event
        self.assertEqual(eevent2, event)

    def test_enrich_event_existing_incident(self):
        event1_metadata = EventMetadata(event_type="test")
        event1 = BaseEvent(event1_metadata, {"joe": "jackson1"})
        self.assertTrue(self.probe.test_event(event1))
        for _ in enrich_event(event1):
            continue
        event2_metadata = EventMetadata(event_type="test")
        event2 = BaseEvent(event2_metadata, {"joe": "jackson2"})
        self.assertTrue(self.probe.test_event(event2))
        enriched_events = list(enrich_event(event2))
        incident = Incident.objects.get(probe_source=self.probe_source)
        self.assertEqual(len(enriched_events), 1)
        eevent = enriched_events[0]
        # enriched event is equal to the 2nd event
        self.assertEqual(eevent, event2)
        # incident present in the original event metadata
        self.assertEqual(len(eevent.metadata.incidents), 1)
        eevent_incident = eevent.metadata.incidents[0]
        self.assertEqual(eevent_incident["pk"], incident.pk)
        self.assertEqual(eevent_incident.get("machine_incident"), None)

    def test_enrich_event_machine_incident_match(self):
        event_metadata = EventMetadata(event_type="test", machine_serial_number="YOLOFOMO")
        event_metadata.machine = MockMetaMachine([self.mbu1], [self.tag1],
                                                 "WINDOWS", "LAPTOP",
                                                 serial_number="YOLOFOMO")
        event = BaseEvent(event_metadata, {"joe": "jackson"})
        self.assertTrue(self.probe.test_event(event))
        enriched_events = list(enrich_event(event))
        self.assertEqual(len(enriched_events), 3)
        eevent1, eevent2, eevent3 = enriched_events
        # first event is the incident event
        self.assertIsInstance(eevent1, IncidentEvent)
        incident = Incident.objects.all()[0]
        self.assertEqual(eevent1.payload["action"], "created")
        self.assertEqual(eevent1.payload["pk"], incident.pk)
        self.assertEqual(eevent1.metadata.machine_serial_number, "YOLOFOMO")
        # second event is the machine incident event
        self.assertIsInstance(eevent2, MachineIncidentEvent)
        self.assertEqual(eevent2.payload["action"], "created")
        self.assertEqual(eevent2.payload["incident"]["pk"], incident.pk)
        self.assertEqual(eevent2.metadata.machine_serial_number, "YOLOFOMO")
        machine_incident = incident.machineincident_set.all()[0]
        self.assertEqual(eevent2.payload["pk"], machine_incident.pk)
        # third event is the original event
        self.assertEqual(eevent3, event)
        # machine incident in the original event metadata incidents
        self.assertEqual(len(eevent3.metadata.incidents), 1)
        eevent3_incident = eevent3.metadata.incidents[0]
        self.assertEqual(eevent3_incident["pk"], machine_incident.incident.pk)
        self.assertEqual(eevent3_incident["machine_incident"]["pk"], machine_incident.pk)

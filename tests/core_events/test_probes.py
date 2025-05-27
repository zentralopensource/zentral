from unittest.mock import patch, Mock
import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.core.events import event_from_event_d
from zentral.core.events.pipeline import enrich_event, process_event
from zentral.core.incidents.models import Incident, IncidentUpdate, MachineIncident, Severity
from zentral.core.probes.conf import all_probes
from zentral.core.probes.models import Action, ActionBackend, ProbeSource


serialized_event = {
    '_zentral': {
        'created_at': '2021-02-18T20:55:00',
        'id': 'ff4db218-d5b4-4c2c-b40b-1b7fdee00dfc',
        'index': 0,
        'machine': {'osquery': {'name': 'perseverance',
                                'os_version': 'VxWorks'},
                    'tags': [{'id': 3, 'name': 'Mars'},
                             {'id': 4, 'name': 'Rover'}],
                    'platform': 'VcWorks',
                    'type': 'ROVER'},
        'machine_serial_number': 'PERSEVERANCE',
        'tags': ['heartbeat'],
        'type': 'inventory_heartbeat',
        'incident_updates': [
            {"incident_type": "munki_reinstall",
             "key": {"munki_pkginfo_name": "SuperApp",
                     "munki_pkginfo_version": "0.1.0"},
             "severity": 300}
        ],
        'objects': {
            'yolo': ["17|42", "11"],
            'machine_incident': ["42"]
        }
    },
    'source': {'module': 'zentral.contrib.jpl', 'name': 'workinprogress'}
}


class EventProbesTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.probe_source = ProbeSource.objects.create(
            model="BaseProbe",
            name=get_random_string(12),
            status=ProbeSource.ACTIVE,
            body={"filters": {"metadata": [{"event_types": ["inventory_heartbeat"]}]}}
        )
        cls.action = Action(
            pk=uuid.uuid4(),
            backend=ActionBackend.HTTP_POST,
            name=get_random_string(12),
        )
        cls.action.set_backend_kwargs({"url": "https://www.example.com/post"})
        cls.action.save()
        cls.probe_source.actions.add(cls.action)
        cls.probe_source_with_incident = ProbeSource.objects.create(
            model="BaseProbe",
            name=get_random_string(12),
            status=ProbeSource.ACTIVE,
            body={"filters": {"metadata": [{"event_types": ["inventory_heartbeat"]}]},
                  "incident_severity": Severity.CRITICAL.value},
        )
        cls.probe_source_for_incident_with_incident = ProbeSource.objects.create(
            model="BaseProbe",
            name=get_random_string(12),
            status=ProbeSource.ACTIVE,
            body={"filters": {"metadata": [{"event_types": ["incident_created"]}]},
                  "incident_severity": Severity.CRITICAL.value},  # only for the tests! Not useful at all!
        )
        cls.probe = cls.probe_source.load()
        cls.probe_with_incident = cls.probe_source_with_incident.load()
        cls.probe_for_incident_with_incident = cls.probe_source_for_incident_with_incident.load()
        all_probes.clear()

    def test_event_from_event_d(self):
        event = event_from_event_d(serialized_event)

        # event type
        self.assertEqual(event.metadata.event_type, "inventory_heartbeat")

        # incident updates
        self.assertEqual(len(event.metadata.incident_updates), 1)
        incident_update = event.metadata.incident_updates[0]
        self.assertEqual(
            incident_update,
            IncidentUpdate(
                "munki_reinstall",
                {"munki_pkginfo_name": "SuperApp", "munki_pkginfo_version": "0.1.0"},
                Severity.CRITICAL
            )
        )

        # linked objects
        self.assertEqual(
            event.metadata.objects,
            {"yolo": [["17", "42"], ["11"]],
             "machine_incident": [["42"]]}
        )

    def test_event_probes(self):
        event = event_from_event_d(serialized_event)
        if self.probe.test_event(event):
            event.metadata.add_probe(self.probe)

        expected_serialized_probes = [{"pk": self.probe.pk, "name": self.probe.name}]
        expected_incident_updates = [
            IncidentUpdate(
                "munki_reinstall",
                {"munki_pkginfo_name": "SuperApp", "munki_pkginfo_version": "0.1.0"},
                Severity.CRITICAL
            )
        ]
        self.assertEqual(event.metadata.probes, expected_serialized_probes)
        self.assertEqual(event.metadata.incident_updates, expected_incident_updates)

        serialized_updated_event = event.serialize()
        self.assertEqual(serialized_updated_event["_zentral"]["probes"], expected_serialized_probes)
        self.assertEqual(
            serialized_updated_event["_zentral"]["incident_updates"],
            [{"incident_type": "munki_reinstall",
              "key": {"munki_pkginfo_name": "SuperApp",
                      "munki_pkginfo_version": "0.1.0"},
              "severity": 300}]
        )

        updated_event = event_from_event_d(serialized_updated_event)
        self.assertEqual(list(updated_event.metadata.iter_loaded_probes()), [self.probe])
        self.assertEqual(updated_event.metadata.incident_updates, expected_incident_updates)

    def test_metadata_tag_filter(self):
        serialized_event = {
            '_zentral': {
                'created_at': '2021-02-18T20:55:00',
                'id': 'ff4db218-d5b4-4c2c-b40b-1b7fdee00dfc',
                'index': 0,
                'tags': ["daslkjdaklasdj", "a-match-haha"],
                'type': 'yolo',
            },
            "yolo": "fomo",
        }
        event = event_from_event_d(serialized_event)
        probe_source = ProbeSource.objects.create(
            model="BaseProbe",
            name=get_random_string(12),
            status=ProbeSource.ACTIVE,
            body={"filters": {"metadata": [{"event_tags": ["daslkjdaklasdj", "not-a-match"]}]}}
        )
        probe = probe_source.load()
        self.assertTrue(probe.test_event(event))

    def test_routing_key_filter(self):
        serialized_event = {
            '_zentral': {
                'created_at': '2021-02-18T20:55:00',
                'id': 'ff4db218-d5b4-4c2c-b40b-1b7fdee00dfc',
                'index': 0,
                'routing_key': "edlkjdlqkjdqe",
                'type': 'yolo',
            },
            "yolo": "fomo",
        }
        event = event_from_event_d(serialized_event)
        probe_source = ProbeSource.objects.create(
            model="BaseProbe",
            name=get_random_string(12),
            status=ProbeSource.ACTIVE,
            body={"filters": {"metadata": [{"event_routing_keys": ["not-a-match", "edlkjdlqkjdqe"]}]}}
        )
        probe = probe_source.load()
        self.assertTrue(probe.test_event(event))

    def test_event_probes_with_probe_incident(self):
        event = event_from_event_d(serialized_event)
        if self.probe_with_incident.test_event(event):
            event.metadata.add_probe(self.probe_with_incident)

        expected_serialized_probes = [{"pk": self.probe_with_incident.pk, "name": self.probe_with_incident.name}]
        expected_incident_updates = [
            IncidentUpdate(
                "munki_reinstall",
                {"munki_pkginfo_name": "SuperApp", "munki_pkginfo_version": "0.1.0"},
                Severity.CRITICAL
            ),
            IncidentUpdate(
                "probe",
                {"probe_pk": self.probe_with_incident.pk},
                Severity(self.probe_with_incident.incident_severity)
            )
        ]
        self.assertEqual(event.metadata.probes, expected_serialized_probes)
        self.assertEqual(event.metadata.incident_updates, expected_incident_updates)

        serialized_updated_event = event.serialize()
        self.assertEqual(serialized_updated_event["_zentral"]["probes"], expected_serialized_probes)
        self.assertEqual(
            serialized_updated_event["_zentral"]["incident_updates"],
            [{"incident_type": "munki_reinstall",
              "key": {"munki_pkginfo_name": "SuperApp",
                      "munki_pkginfo_version": "0.1.0"},
              "severity": 300},
             {"incident_type": "probe",
              "key": {"probe_pk": self.probe_with_incident.pk},
              "severity": 300}]
        )

        updated_event = event_from_event_d(serialized_updated_event)
        self.assertEqual(list(updated_event.metadata.iter_loaded_probes()), [self.probe_with_incident])
        self.assertEqual(updated_event.metadata.incident_updates, expected_incident_updates)

    def test_event_probes_with_probe_incident_without_incident_updates(self):
        event = event_from_event_d(serialized_event)
        if self.probe_with_incident.test_event(event):
            event.metadata.add_probe(self.probe_with_incident, with_incident_updates=False)

        expected_serialized_probes = [{"pk": self.probe_with_incident.pk, "name": self.probe_with_incident.name}]
        expected_incident_updates = [
            IncidentUpdate(
                "munki_reinstall",
                {"munki_pkginfo_name": "SuperApp", "munki_pkginfo_version": "0.1.0"},
                Severity.CRITICAL
            )
        ]
        self.assertEqual(event.metadata.probes, expected_serialized_probes)
        self.assertEqual(event.metadata.incident_updates, expected_incident_updates)

        serialized_updated_event = event.serialize()
        self.assertEqual(serialized_updated_event["_zentral"]["probes"], expected_serialized_probes)
        self.assertEqual(
            serialized_updated_event["_zentral"]["incident_updates"],
            [{"incident_type": "munki_reinstall",
              "key": {"munki_pkginfo_name": "SuperApp",
                      "munki_pkginfo_version": "0.1.0"},
              "severity": 300}]
        )

        updated_event = event_from_event_d(serialized_updated_event)
        self.assertEqual(list(updated_event.metadata.iter_loaded_probes()), [self.probe_with_incident])
        self.assertEqual(updated_event.metadata.incident_updates, expected_incident_updates)

    def test_enrich_event(self):
        events = list(enrich_event(serialized_event))
        self.assertEqual(len(events), 5)

        munki_incident_type = "munki_reinstall"
        munki_incident_key = {
            "munki_pkginfo_name": "SuperApp",
            "munki_pkginfo_version": "0.1.0"
        }
        munki_incident = Incident.objects.get(incident_type=munki_incident_type, key=munki_incident_key)
        munki_machine_incident = MachineIncident.objects.get(incident=munki_incident)

        event0 = events[0]
        self.assertEqual(event0.metadata.event_type, "incident_created")
        self.assertEqual(event0.payload["type"], munki_incident_type)
        self.assertEqual(event0.payload["key"], munki_incident_key)
        self.assertEqual(event0.payload["pk"], munki_incident.pk)

        event1 = events[1]
        self.assertEqual(event1.metadata.event_type, "machine_incident_created")
        self.assertEqual(event1.payload["type"], munki_incident_type)
        self.assertEqual(event1.payload["key"], munki_incident_key)
        self.assertEqual(event1.payload["pk"], munki_incident.pk)
        self.assertEqual(event1.payload["machine_incident"]["pk"], munki_machine_incident.pk)

        probe_incident_type = "probe"
        probe_incident_key = {"probe_pk": self.probe_source_with_incident.pk}
        probe_incident = Incident.objects.get(incident_type=probe_incident_type, key=probe_incident_key)
        probe_machine_incident = MachineIncident.objects.get(incident=probe_incident)

        event2 = events[2]
        self.assertEqual(event2.metadata.event_type, "incident_created")
        self.assertEqual(event2.payload["type"], probe_incident_type)
        self.assertEqual(event2.payload["key"], probe_incident_key)
        self.assertEqual(event2.payload["pk"], probe_incident.pk)
        self.assertEqual(event2.metadata.probes,
                         [self.probe_for_incident_with_incident.serialize_for_event_metadata()])

        event3 = events[3]
        self.assertEqual(event3.metadata.event_type, "machine_incident_created")
        self.assertEqual(event3.payload["type"], probe_incident_type)
        self.assertEqual(event3.payload["key"], probe_incident_key)
        self.assertEqual(event3.payload["pk"], probe_incident.pk)
        self.assertEqual(event3.payload["machine_incident"]["pk"], probe_machine_incident.pk)

        event4 = events[4]
        self.assertEqual(event4.metadata.event_type, "inventory_heartbeat")
        self.assertEqual(
            sorted(event4.metadata.probes, key=lambda d: d["pk"]),
            sorted(
                [self.probe.serialize_for_event_metadata(),
                 self.probe_with_incident.serialize_for_event_metadata()],
                key=lambda d: d["pk"]
            )
        )

        # one more time, only the original event, no incident events
        events = list(enrich_event(serialized_event))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].metadata.event_type, "inventory_heartbeat")

    @patch("zentral.core.probes.action_backends.http.requests.Session.post")
    def test_process_event(self, session_post):
        response = Mock()
        session_post.return_value = response
        event = list(enrich_event(serialized_event))[4]
        self.assertEqual(event.metadata.event_type, "inventory_heartbeat")
        process_event(event.serialize())  # to force deserialization
        session_post.assert_called_once_with(
            "https://www.example.com/post",
            json=event.serialize(),
        )
        response.raise_for_status.assert_called_once()

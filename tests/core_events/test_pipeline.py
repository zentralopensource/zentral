import uuid
from unittest.mock import Mock, patch
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MachineSnapshotCommit, MetaBusinessUnit
from zentral.core.events.base import EventMetadata, EventRequest
from zentral.core.events.pipeline import enrich_event, get_city, process_event
from zentral.core.probes.conf import all_probes


class EnrichEventMetaBusinessUnitsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu1 = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu2 = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.serial_number = get_random_string(12)
        cls._commit(cls.serial_number, "a", cls.mbu1.create_enrollment_business_unit().serialize())
        cls._commit(cls.serial_number, "b", cls.mbu2.create_enrollment_business_unit().serialize())
        all_probes.clear()

    @staticmethod
    def _commit(serial_number, source_name, business_unit_tree=None):
        tree = {"source": {"module": "tests.zentral.io", "name": source_name}, "serial_number": serial_number}
        if business_unit_tree:
            tree["business_unit"] = business_unit_tree
        MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)

    def _event_d(self, serial_number=None, objects=None, incident_updates=None):
        metadata = {
            "created_at": "2026-11-08T10:00:00",
            "id": str(uuid.uuid4()),
            "index": 0,
            "type": "inventory_heartbeat",
        }
        if serial_number:
            metadata["machine_serial_number"] = serial_number
        if objects:
            metadata["objects"] = objects
        if incident_updates:
            metadata["incident_updates"] = incident_updates
        return {"_zentral": metadata, "source": {"module": "tests.zentral.io", "name": "tests"}}

    def test_meta_business_units(self):
        events = list(enrich_event(self._event_d(self.serial_number)))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.metadata.objects["meta_business_unit"], [(self.mbu1.pk,), (self.mbu2.pk,)])
        self.assertEqual(
            event.serialize()["_zentral"]["objects"]["meta_business_unit"],
            [str(self.mbu1.pk), str(self.mbu2.pk)]
        )

    def test_meta_business_units_before_probe_matching(self):
        seen_objects = []

        def event_filtered(event):
            seen_objects.append(dict(event.metadata.objects))
            return []

        with patch.object(all_probes, "event_filtered", side_effect=event_filtered):
            list(enrich_event(self._event_d(self.serial_number)))
        self.assertEqual(seen_objects, [{"meta_business_unit": [(self.mbu1.pk,), (self.mbu2.pk,)]}])

    def test_meta_business_units_not_duplicated(self):
        event_d = self._event_d(self.serial_number, objects={"meta_business_unit": [str(self.mbu1.pk)]})
        event = list(enrich_event(event_d))[0]
        self.assertEqual(
            event.serialize()["_zentral"]["objects"]["meta_business_unit"],
            [str(self.mbu1.pk), str(self.mbu2.pk)]
        )

    def test_no_machine(self):
        event = list(enrich_event(self._event_d()))[0]
        self.assertNotIn("objects", event.serialize()["_zentral"])

    def test_machine_without_meta_business_unit(self):
        serial_number = get_random_string(12)
        self._commit(serial_number, "a")
        event = list(enrich_event(self._event_d(serial_number)))[0]
        self.assertNotIn("objects", event.serialize()["_zentral"])

    def test_unknown_machine(self):
        event = list(enrich_event(self._event_d(get_random_string(12))))[0]
        self.assertNotIn("objects", event.serialize()["_zentral"])

    def test_incident_events_meta_business_units(self):
        event_d = self._event_d(
            self.serial_number,
            incident_updates=[{"incident_type": "munki_reinstall",
                               "key": {"munki_pkginfo_name": get_random_string(12),
                                       "munki_pkginfo_version": "1.0"},
                               "severity": 300}],
        )
        events = list(enrich_event(event_d))
        self.assertEqual([e.metadata.event_type for e in events],
                         ["incident_created", "machine_incident_created", "inventory_heartbeat"])
        for event in events:
            self.assertEqual(event.metadata.objects["meta_business_unit"], [(self.mbu1.pk,), (self.mbu2.pk,)])


class EventMetadataAddObjectsTestCase(TestCase):
    def test_add_objects_compares_the_encoded_args(self):
        metadata = EventMetadata(objects={"yolo": [["17", "42"], ["11"]]})
        metadata.add_objects({"yolo": [(17, 42), (11,), (12,), (12,)], "fomo": [(1,)]})
        self.assertEqual(metadata.objects, {"yolo": [["17", "42"], ["11"], (12,)], "fomo": [(1,)]})


class EnrichEventGeoTestCase(TestCase):
    event_d = {
        "_zentral": {
            "created_at": "2026-11-08T10:00:00",
            "id": "ff4db218-d5b4-4c2c-b40b-1b7fdee00dfc",
            "index": 0,
            "type": "inventory_heartbeat",
            "request": {"user_agent": "tests", "ip": "192.0.2.1"},
        },
    }

    @patch("zentral.core.events.pipeline.city_db_reader")
    def test_get_city(self, city_db_reader):
        city = Mock()
        city_db_reader.city.return_value = city
        self.assertEqual(get_city("192.0.2.1"), city)
        city_db_reader.city.assert_called_once_with("192.0.2.1")

    @patch("zentral.core.events.pipeline.city_db_reader")
    def test_get_city_error(self, city_db_reader):
        city_db_reader.city.side_effect = ValueError("unknown address")
        self.assertIsNone(get_city("192.0.2.1"))

    @patch.object(EventRequest, "set_geo_from_city")
    @patch("zentral.core.events.pipeline.get_city")
    @patch("zentral.core.events.pipeline.city_db_reader")
    def test_geo(self, city_db_reader, get_city, set_geo_from_city):
        city = Mock()
        get_city.return_value = city
        list(enrich_event(self.event_d))
        get_city.assert_called_once_with("192.0.2.1")
        set_geo_from_city.assert_called_once_with(city)

    @patch.object(EventRequest, "set_geo_from_city")
    @patch("zentral.core.events.pipeline.get_city")
    @patch("zentral.core.events.pipeline.city_db_reader")
    def test_geo_unknown_city(self, city_db_reader, get_city, set_geo_from_city):
        get_city.return_value = None
        list(enrich_event(self.event_d))
        get_city.assert_called_once_with("192.0.2.1")
        set_geo_from_city.assert_not_called()


class ProcessEventTestCase(TestCase):
    def test_action_error(self):
        event = list(enrich_event(EnrichEventGeoTestCase.event_d))[0]
        action = Mock()
        action.trigger.side_effect = ValueError("action error")
        probe = Mock(loaded_actions=[action])
        with patch.object(EventMetadata, "iter_loaded_probes", return_value=[probe]):
            with self.assertLogs("zentral.core.events.pipeline", level="ERROR") as cm:
                process_event(event.serialize())
        action.trigger.assert_called_once()
        self.assertEqual(len(cm.output), 1)
        self.assertIn("Could not trigger action", cm.output[0])

from unittest.mock import patch
from django.db import OperationalError
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.events import post_machine_snapshot_raw_event, AddMachine, InventoryHeartbeat
from zentral.contrib.inventory.models import MachineSnapshot
from zentral.contrib.inventory.preprocessors import get_preprocessors, MachineSnapshotPreprocessor
from zentral.core.queues.exceptions import RetryLater


class InventoryPreprocessorsTestCase(TestCase):
    @patch("zentral.contrib.inventory.events.queues")
    def test_post_machine_snapshot_raw_event(self, queues):
        ms_tree = {"serial_number": "012345678910"}
        post_machine_snapshot_raw_event(ms_tree)
        queues.post_raw_event.assert_called_once_with(MachineSnapshotPreprocessor.routing_key, {"ms_tree": ms_tree})

    def test_get_preprocessors(self):
        preprocessors = list(get_preprocessors())
        self.assertEqual(len(preprocessors), 1)
        self.assertIsInstance(preprocessors[0], MachineSnapshotPreprocessor)

    def test_process_raw_machine_snapshot(self):
        pp = MachineSnapshotPreprocessor()
        serial_number = get_random_string(12)
        computer_name = get_random_string(12)
        events = list(pp.process_raw_event(
            {"ms_tree": {"serial_number": serial_number,
                         "reference": serial_number,
                         "source": {"module": "zentral.contrib.munki",
                                    "name": "Munki"},
                         "system_info": {"computer_name": computer_name}}}
        ))
        self.assertEqual(len(events), 2)
        self.assertIsInstance(events[0], AddMachine)
        self.assertIsInstance(events[1], InventoryHeartbeat)
        ms = MachineSnapshot.objects.current().get(serial_number=serial_number)
        self.assertEqual(ms.system_info.computer_name, computer_name)

    def test_process_raw_machine_snapshot_deterministic_error_dropped(self):
        pp = MachineSnapshotPreprocessor()
        serial_number = get_random_string(12)
        with self.assertLogs("zentral.contrib.inventory.preprocessors", level="ERROR") as cm:
            events = list(pp.process_raw_event(
                {"ms_tree": {"serial_number": serial_number,
                             "reference": serial_number,
                             "source": {"module": "zentral.contrib.munki",
                                        "name": "Munki"},
                             "yolo": "fomo"}}
            ))
        self.assertEqual(events, [])
        self.assertEqual(len(cm.output), 1)
        self.assertIn(f"Source Munki, serial number {serial_number}: machine snapshot tree dropped", cm.output[0])
        self.assertIn("yolo", cm.output[0])
        self.assertNotIn("Traceback", cm.output[0])
        self.assertFalse(MachineSnapshot.objects.filter(serial_number=serial_number).exists())

    def test_process_raw_machine_snapshot_missing_tree_dropped(self):
        pp = MachineSnapshotPreprocessor()
        with self.assertLogs("zentral.contrib.inventory.preprocessors", level="ERROR") as cm:
            events = list(pp.process_raw_event({}))
        self.assertEqual(events, [])
        self.assertEqual(len(cm.output), 1)
        self.assertIn("Source UNKNOWN, serial number UNKNOWN: machine snapshot tree dropped", cm.output[0])

    @patch("zentral.contrib.inventory.preprocessors.commit_machine_snapshot_and_yield_events")
    def test_process_raw_machine_snapshot_retry_later_passthrough(self, cmsaye):
        cmsaye.side_effect = RetryLater
        pp = MachineSnapshotPreprocessor()
        with self.assertNoLogs("zentral.contrib.inventory.preprocessors", level="ERROR"):
            with self.assertRaises(RetryLater):
                list(pp.process_raw_event({"ms_tree": {"serial_number": get_random_string(12)}}))

    @patch("zentral.contrib.inventory.preprocessors.commit_machine_snapshot_and_yield_events")
    def test_process_raw_machine_snapshot_db_error_propagates(self, cmsaye):
        cmsaye.side_effect = OperationalError("server closed the connection unexpectedly")
        pp = MachineSnapshotPreprocessor()
        # transient DB errors are re-raised, not dropped, so the worker recycles the
        # connection and re-enqueues (see zentral.core.queues.preprocessing)
        with self.assertNoLogs("zentral.contrib.inventory.preprocessors", level="ERROR"):
            with self.assertRaises(OperationalError):
                list(pp.process_raw_event(
                    {"ms_tree": {"serial_number": get_random_string(12),
                                 "source": {"module": "zentral.contrib.munki",
                                            "name": "Munki"}}}
                ))

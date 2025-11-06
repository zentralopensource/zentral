from unittest.mock import patch
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.events import post_machine_snapshot_raw_event, AddMachine, InventoryHeartbeat
from zentral.contrib.inventory.models import MachineSnapshot
from zentral.contrib.inventory.preprocessors import get_preprocessors, MachineSnapshotPreprocessor


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

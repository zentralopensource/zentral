from unittest.mock import patch
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.events import AddMachine, InventoryHeartbeat
from zentral.contrib.inventory.models import MachineSnapshot
from zentral.contrib.inventory.utils import (commit_machine_snapshot_and_trigger_events,
                                             commit_machine_snapshot_and_yield_events)


class InventoryUtilsDBTestCase(TestCase):
    def _create_machine_snapshot_tree(self, serial_number=None):
        if serial_number is None:
            serial_number = get_random_string(12)
        source = {
            "module": "tests.zentral.com",
            "name": "Zentral Tests",
        }
        return serial_number, {
            "source": source,
            "business_unit": {
                "name": "yolo",
                "reference": "fomo",
                "source": source},
            "serial_number": serial_number,
        }

    @patch("zentral.contrib.inventory.utils.db.MachineSnapshotCommit")
    def test_commit_machine_snapshot_and_trigger_events_error(self, msc):
        msc.objects.commit_machine_snapshot_tree.side_effect = ValueError("BOOM!")
        serial_number, tree = self._create_machine_snapshot_tree()
        with self.assertRaises(ValueError) as cm:
            commit_machine_snapshot_and_trigger_events(tree)
        self.assertEqual(cm.exception.args[0], "BOOM!")
        self.assertFalse(MachineSnapshot.objects.filter(serial_number=serial_number).exists())

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_commit_machine_snapshot_and_trigger_events(self, post_event):
        serial_number, tree = self._create_machine_snapshot_tree()
        commit_machine_snapshot_and_trigger_events(tree)
        self.assertEqual(len(post_event.call_args_list), 2)
        self.assertIsInstance(post_event.call_args_list[0].args[0], AddMachine)
        self.assertIsInstance(post_event.call_args_list[1].args[0], InventoryHeartbeat)
        self.assertTrue(MachineSnapshot.objects.filter(serial_number=serial_number).exists())

    @patch("zentral.contrib.inventory.utils.db.MachineSnapshotCommit")
    def test_commit_machine_snapshot_and_yield_events_error(self, msc):
        msc.objects.commit_machine_snapshot_tree.side_effect = ValueError("BOOM!")
        serial_number, tree = self._create_machine_snapshot_tree()
        with self.assertRaises(ValueError) as cm:
            list(commit_machine_snapshot_and_yield_events(tree))
        self.assertEqual(cm.exception.args[0], "BOOM!")
        self.assertFalse(MachineSnapshot.objects.filter(serial_number=serial_number).exists())

    def test_commit_machine_snapshot_and_yield_events(self):
        serial_number, tree = self._create_machine_snapshot_tree()
        events = list(commit_machine_snapshot_and_yield_events(tree))
        self.assertEqual(len(events), 2)
        self.assertIsInstance(events[0], AddMachine)
        self.assertIsInstance(events[1], InventoryHeartbeat)
        self.assertTrue(MachineSnapshot.objects.filter(serial_number=serial_number).exists())

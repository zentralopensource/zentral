from unittest.mock import patch
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.events import AddMachine, ArchiveMachine, InventoryHeartbeat
from zentral.contrib.inventory.models import CurrentMachineSnapshot, MachineSnapshot, Source
from zentral.contrib.inventory.utils import (archive_machine_snapshots,
                                             archive_machine_snapshots_and_yield_events,
                                             commit_machine_snapshot_and_trigger_events,
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

    # archive machine snapshots

    def _commit_two_sources(self, serial_number=None):
        serial_number, tree = self._create_machine_snapshot_tree(serial_number)
        commit_machine_snapshot_and_trigger_events(tree)
        other_source = {"module": "tests.zentral.com", "name": "Zentral Other Tests"}
        commit_machine_snapshot_and_trigger_events({"source": other_source, "serial_number": serial_number})
        return serial_number

    def test_archive_machine_snapshots_all_sources(self):
        serial_number = self._commit_two_sources()
        self.assertEqual(CurrentMachineSnapshot.objects.filter(serial_number=serial_number).count(), 2)
        events = list(archive_machine_snapshots_and_yield_events([serial_number]))
        self.assertEqual(CurrentMachineSnapshot.objects.filter(serial_number=serial_number).count(), 0)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, ArchiveMachine)
        self.assertEqual(event.metadata.machine_serial_number, serial_number)
        self.assertEqual(
            event.payload,
            {"sources": [{"module": "tests.zentral.com", "name": "Zentral Other Tests"},
                         {"module": "tests.zentral.com", "name": "Zentral Tests"}]}
        )

    def test_archive_machine_snapshots_one_source_only(self):
        serial_number = self._commit_two_sources()
        source = Source.objects.get(module="tests.zentral.com", name="Zentral Tests")
        events = list(archive_machine_snapshots_and_yield_events([serial_number], sources=[source]))
        self.assertEqual(len(events), 1)
        self.assertEqual(
            events[0].payload,
            {"sources": [{"module": "tests.zentral.com", "name": "Zentral Tests"}]}
        )
        # the other source is untouched
        remaining = list(CurrentMachineSnapshot.objects.filter(serial_number=serial_number)
                                                       .select_related("source"))
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0].source.name, "Zentral Other Tests")

    def test_archive_machine_snapshots_keeps_the_snapshots(self):
        serial_number = self._commit_two_sources()
        snapshot_count = MachineSnapshot.objects.filter(serial_number=serial_number).count()
        list(archive_machine_snapshots_and_yield_events([serial_number]))
        self.assertEqual(MachineSnapshot.objects.filter(serial_number=serial_number).count(), snapshot_count)

    def test_archive_machine_snapshots_unknown_serial_number(self):
        events = list(archive_machine_snapshots_and_yield_events([get_random_string(12)]))
        self.assertEqual(events, [])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_archive_machine_snapshots_posts_events_and_counts(self, post_event):
        serial_number = self._commit_two_sources()
        post_event.reset_mock()
        self.assertEqual(archive_machine_snapshots([serial_number]), 2)
        self.assertEqual(len(post_event.call_args_list), 1)
        self.assertIsInstance(post_event.call_args_list[0].args[0], ArchiveMachine)

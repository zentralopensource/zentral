from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils.crypto import get_random_string

from zentral.contrib.inventory.events import InventorySourceHealthEvent
from zentral.contrib.inventory.incidents import InventorySourceStaleIncident
from zentral.contrib.inventory.models import CurrentMachineSnapshot, MachineSnapshotCommit
from zentral.contrib.inventory.watches import InventorySourceStaleWatch
from zentral.core.incidents.models import Severity
from zentral.core.watchers.events import SubjectUnwatchedEvent
from zentral.core.watchers.models import WatchState
from zentral.utils.time import naive_utcnow


class InventorySourceStaleWatchTestCase(TestCase):
    def setUp(self):
        self.watch = InventorySourceStaleWatch()

    # utility methods

    def _force_snapshot(self, age_days=None, source_name=None):
        serial_number = get_random_string(12)
        tree = {"source": {"module": "tests.inventory", "name": source_name or get_random_string(12)},
                "serial_number": serial_number}
        _, machine_snapshot, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        cms = CurrentMachineSnapshot.objects.get(serial_number=serial_number,
                                                 source=machine_snapshot.source)
        if age_days is not None:
            self._age(cms, age_days)
        return cms

    def _age(self, cms, days):
        CurrentMachineSnapshot.objects.filter(pk=cms.pk).update(
            last_seen=naive_utcnow() - timedelta(days=days)
        )

    @staticmethod
    def _subject_id(cms):
        return str(cms.pk)

    def _state(self, cms):
        return WatchState.objects.get(watch=self.watch.name, subject_id=self._subject_id(cms))

    def _run(self):
        with self.captureOnCommitCallbacks(execute=True):
            result = self.watch.run_once()
        # the three counts these tests are about, so a new one does not rewrite every assertion below
        return result.changed, result.recovered, result.events

    # nothing to report

    def test_fresh_snapshot_is_not_stale(self):
        cms = self._force_snapshot()
        changed, recovered, events = self._run()
        self.assertEqual((changed, recovered, events), (0, 0, 0))
        self.assertFalse(WatchState.objects.filter(subject_id=self._subject_id(cms)).exists())

    def test_just_inside_the_period_is_not_stale(self):
        self._force_snapshot(age_days=6)
        self.assertEqual(self.watch.run_once()[0], 0)

    # degradation

    def test_stale_snapshot_fires_once(self):
        cms = self._force_snapshot(age_days=8)
        with patch.object(InventorySourceHealthEvent, "post") as post:
            changed, recovered, events = self._run()
        self.assertEqual((changed, recovered, events), (1, 0, 1))
        self.assertEqual(post.call_count, 1)
        state = self._state(cms)
        self.assertEqual(state.reasons, ["stale"])
        self.assertEqual(state.previous_reasons, [])
        self.assertEqual(state.serial_number, cms.serial_number)
        self.assertEqual(state.severity, Severity.MAJOR.value)
        # still stale on the next tick, but the conclusion has not changed, so nothing fires again
        with patch.object(InventorySourceHealthEvent, "post") as post:
            self.assertEqual(self._run(), (0, 0, 0))
        self.assertEqual(post.call_count, 0)

    def test_stale_event_payload_and_incident(self):
        cms = self._force_snapshot(age_days=8)
        events = []
        with patch.object(InventorySourceHealthEvent, "post", lambda self: events.append(self)):
            self._run()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.payload["source"],
                         {"pk": cms.source.pk, "name": cms.source.name,
                          "module": cms.source.module})
        self.assertEqual(event.payload["period"], self.watch.period)
        # same event type as the recovery: `status` is what tells them apart
        self.assertEqual(event.payload["status"], "degraded")
        # how long it has been stale so far — the same field the recovery uses to say how long it was
        self.assertGreaterEqual(event.payload["degraded_for"], 0)
        # same names and same arrays as the state row, and as every other watch event
        self.assertEqual(event.payload["reasons"], ["stale"])
        self.assertEqual(event.payload["previous_reasons"], [])
        self.assertIn("watch", event.tags)
        # a machine serial on the metadata is what makes this a MachineIncident downstream
        self.assertEqual(event.metadata.machine_serial_number, cms.serial_number)
        incident_update = event.metadata.incident_updates[0]
        self.assertEqual(incident_update.incident_type, "inventory_source_stale")
        self.assertEqual(incident_update.key, {"inventory_source_pk": cms.source.pk})
        self.assertEqual(incident_update.severity, Severity.MAJOR)
        # linked to the source, so it lands on that source's event page
        self.assertEqual(event.get_linked_objects_keys(), {"inventory_source": [(cms.source.pk,)]})

    def test_one_event_per_source_not_per_machine(self):
        # a machine reporting from two sources, both quiet, is two events — per source is the actionable
        # grain, and a machine-level roll-up would hide the interesting case
        serial_number = get_random_string(12)
        for _ in range(2):
            tree = {"source": {"module": "tests.inventory", "name": get_random_string(12)},
                    "serial_number": serial_number}
            MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        CurrentMachineSnapshot.objects.filter(serial_number=serial_number).update(
            last_seen=naive_utcnow() - timedelta(days=8)
        )
        changed, _, events = self._run()
        self.assertEqual((changed, events), (2, 2))

    # recovery

    def test_recovery_deletes_the_state_and_closes_the_incident(self):
        cms = self._force_snapshot(age_days=8)
        self._run()
        first_fired_at = self._state(cms).first_fired_at
        self._age(cms, 0)
        events = []
        with patch.object(InventorySourceHealthEvent, "post", lambda self: events.append(self)):
            changed, recovered, event_count = self._run()
        self.assertEqual((changed, recovered, event_count), (0, 1, 1))
        self.assertFalse(WatchState.objects.filter(watch=self.watch.name,
                                                   subject_id=self._subject_id(cms)).exists())
        event = events[0]
        self.assertEqual(event.payload["source"],
                         {"pk": cms.source.pk, "name": cms.source.name,
                          "module": cms.source.module})
        self.assertEqual(event.payload["status"], "recovered")
        # healthy is the empty array, which the sparse table never stores
        self.assertEqual(event.payload["reasons"], [])
        self.assertEqual(event.payload["previous_reasons"], ["stale"])
        self.assertIn("watch", event.tags)
        self.assertGreaterEqual(event.payload["degraded_for"], 0)
        self.assertLessEqual(
            event.payload["degraded_for"], int((naive_utcnow() - first_fired_at).total_seconds()) + 1
        )
        # Severity.NONE is what closes the incident — there is no separate close call
        self.assertEqual(event.metadata.incident_updates[0].severity, Severity.NONE)
        self.assertEqual(event.metadata.machine_serial_number, cms.serial_number)

    def test_an_archived_machine_closes_its_incident_without_recovering(self):
        cms = self._force_snapshot(age_days=8)
        self._run()
        subject_id = self._subject_id(cms)
        source_pk = cms.source_id
        serial_number = cms.serial_number
        # the key was captured on insert, while the snapshot still existed
        self.assertEqual(self._state(cms).incident_key, {"inventory_source_pk": source_pk})
        # this is what MetaMachine.archive() does: the snapshot row is DELETED, taking the source pk
        # with it — only the stored key survives
        cms.delete()
        unwatched = []
        with patch.object(InventorySourceHealthEvent, "post") as recovered_post:
            with patch.object(SubjectUnwatchedEvent, "post",
                              lambda self: unwatched.append(self)):
                changed, recovered, events = self._run()
        # it did not recover, so no recovery event — but the incident IS closed, or nothing ever could:
        # the state row is gone and no later tick will emit about this pair again
        self.assertEqual((changed, recovered, events), (0, 0, 1))
        self.assertEqual(recovered_post.call_count, 0)
        self.assertFalse(
            WatchState.objects.filter(watch=self.watch.name, subject_id=subject_id).exists()
        )
        event = unwatched[0]
        incident_update = event.metadata.incident_updates[0]
        self.assertEqual(incident_update.incident_type, InventorySourceStaleIncident.incident_type)
        # the source pk outlived the snapshot, which is the whole point of storing the key
        self.assertEqual(incident_update.key, {"inventory_source_pk": source_pk})
        self.assertEqual(incident_update.severity, Severity.NONE)
        self.assertEqual(event.metadata.machine_serial_number, serial_number)
        self.assertEqual(event.payload["status"], "unwatched")
        self.assertEqual(event.payload["watch"], self.watch.name)
        self.assertEqual(event.payload["reasons"], ["stale"])
        # NOT linked to the source: the close is a fact about the watch, and the machine — which is
        # what an operator investigates when one is archived — is still on the metadata
        self.assertEqual(event.metadata.objects, {})
        self.assertEqual(event.metadata.machine_serial_number, serial_number)

    # incident class

    def test_incident_get_objects_and_name(self):
        cms = self._force_snapshot()
        incident = InventorySourceStaleIncident(
            type("I", (), {"key": InventorySourceStaleIncident.get_incident_key(cms.source.pk),
                           "pk": 1})()
        )
        self.assertEqual(incident.get_objects(), [cms.source])
        self.assertEqual(incident.get_name(), f"{cms.source.name} inventory stopped reporting")
        display = list(incident.get_objects_for_display())
        self.assertEqual(display[0][0], "Inventory source")
        self.assertEqual(display[0][2], [cms.source])

    def test_incident_with_an_unknown_source(self):
        incident = InventorySourceStaleIncident(
            type("I", (), {"key": {"inventory_source_pk": 1234567}, "pk": 1})()
        )
        self.assertEqual(incident.get_objects(), [])
        self.assertEqual(incident.get_name(), "Unknown inventory source stopped reporting")
        self.assertEqual(list(incident.get_objects_for_display()), [])

    def test_incident_with_a_malformed_key(self):
        incident = InventorySourceStaleIncident(type("I", (), {"key": {"yolo": "fomo"}, "pk": 1})())
        self.assertEqual(incident.get_objects(), [])

    # the source lookup

    def test_sources_lookup_is_empty_without_rows(self):
        self.assertEqual(InventorySourceStaleWatch.get_subjects([]), {})

from collections import namedtuple
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils.crypto import get_random_string

from zentral.core.events.base import BaseEvent, EventMetadata
from zentral.core.incidents.models import Severity
from zentral.core.watchers.events import SubjectUnwatchedEvent
from zentral.core.watchers.models import WatchState
from zentral.core.watchers.watches import BaseWatch
from zentral.utils.time import naive_utcnow


class ProtocolTestEvent(BaseEvent):
    event_type = "zentral_watchers_protocol_test"


class _FakeSubjectWatch(BaseWatch):
    """A watch over WatchState rows of another watch, so the protocol can be exercised with no module.

    The subject table is watchers_watchstate itself: rows tagged `_subjects` stand in for watched objects,
    and their `reasons` array is the source data the watch reads.
    """
    name = "_protocol_test"
    interval = 1
    severities = {"a": 100, "b": 300}

    degraded_select = (
        "SELECT %(watch)s, src.subject_id, src.serial_number,"
        "       src.reasons, ARRAY[]::varchar[], %(severity)s,"
        "       jsonb_build_object('subject_id', src.subject_id), NOW(), NOW() "
        "  FROM watchers_watchstate AS src"
        " WHERE src.watch = '_subjects' AND cardinality(src.reasons) > 0"
    )
    still_degraded = (
        "SELECT 1 FROM watchers_watchstate AS src"
        " WHERE src.watch = '_subjects' AND src.subject_id = ws.subject_id"
        "   AND cardinality(src.reasons) > 0"
    )
    subject_alive = (
        "SELECT 1 FROM watchers_watchstate AS src"
        " WHERE src.watch = '_subjects' AND src.subject_id = ws.subject_id"
    )

    def get_query_kwargs(self):
        kwargs = super().get_query_kwargs()
        kwargs["severity"] = 100
        return kwargs

    def iter_events(self, changed, recovered):
        for row in changed:
            yield ProtocolTestEvent(
                EventMetadata(machine_serial_number=row.serial_number),
                {"kind": "degraded", "reasons": row.reasons, "previous_reasons": row.previous_reasons},
            )
        for row in recovered:
            yield ProtocolTestEvent(
                EventMetadata(machine_serial_number=row.serial_number),
                {"kind": "recovered", "reasons": row.reasons},
            )


class _FakeTriggerWatch(_FakeSubjectWatch):
    """Core's default emission, and no incident_class — a watch may be a pure trigger.

    iter_events is restored to the base one: _FakeSubjectWatch overrides it to exercise the protocol
    without core's event building, which is the opposite of what this one is for.
    """
    event_class = ProtocolTestEvent
    iter_events = BaseWatch.iter_events


class _ProtocolTestIncident:
    incident_type = "_protocol_test_incident"


class _FakeIncidentWatch(_FakeSubjectWatch):
    "Same protocol, but it opens incidents — so core has something to close when a subject goes unwatched."
    incident_class = _ProtocolTestIncident


_Row = namedtuple("_Row",
                  ["watch", "subject_id", "serial_number", "reasons", "previous_reasons",
                   "incident_key", "severity", "first_fired_at"])


class WatchProtocolTestCase(TestCase):
    def setUp(self):
        self.watch = _FakeSubjectWatch()

    # utility

    def _subject(self, reasons, subject_id=None, serial_number=None):
        subject_id = subject_id or get_random_string(12)
        WatchState.objects.update_or_create(
            watch="_subjects", subject_id=subject_id,
            defaults={"serial_number": serial_number or get_random_string(12),
                      "reasons": reasons,
                      "severity": None,
                      "first_fired_at": naive_utcnow(),
                      "fired_at": naive_utcnow()},
        )
        return subject_id

    def _state(self, subject_id):
        return WatchState.objects.get(watch=self.watch.name, subject_id=subject_id)

    def _run(self):
        with self.captureOnCommitCallbacks(execute=True):
            result = self.watch.run_once()
        # the three counts these tests are about, so a new one does not rewrite every assertion below
        return result.changed, result.recovered, result.events

    # a first crossing

    def test_first_crossing_inserts_and_emits(self):
        subject_id = self._subject(["a"])
        with patch.object(ProtocolTestEvent, "post") as post:
            changed, recovered, events = self._run()
        self.assertEqual((changed, recovered, events), (1, 0, 1))
        self.assertEqual(post.call_count, 1)
        state = self._state(subject_id)
        self.assertEqual(state.reasons, ["a"])
        self.assertEqual(state.previous_reasons, [])

    def test_unchanged_conclusion_emits_nothing(self):
        self._subject(["a"])
        self._run()
        with patch.object(ProtocolTestEvent, "post") as post:
            changed, recovered, events = self._run()
        # the row is already there with the same reasons: IS DISTINCT FROM is false, nothing returns
        self.assertEqual((changed, recovered, events), (0, 0, 0))
        self.assertEqual(post.call_count, 0)

    # a changed conclusion

    def test_changed_conclusion_carries_both_sides(self):
        subject_id = self._subject(["a"])
        self._run()
        self._subject(["b"], subject_id=subject_id)
        changed, _, events = self._run()
        self.assertEqual((changed, events), (1, 1))
        state = self._state(subject_id)
        self.assertEqual(state.reasons, ["b"])
        self.assertEqual(state.previous_reasons, ["a"])

    def test_first_fired_at_is_not_moved_by_a_later_transition(self):
        subject_id = self._subject(["a"])
        self._run()
        first_fired_at = self._state(subject_id).first_fired_at
        WatchState.objects.filter(watch=self.watch.name, subject_id=subject_id).update(
            first_fired_at=first_fired_at - timedelta(days=3)
        )
        expected = self._state(subject_id).first_fired_at
        self._subject(["b"], subject_id=subject_id)
        self._run()
        # first_fired_at answers "how long has it been bad", so an escalation must not reset it
        self.assertEqual(self._state(subject_id).first_fired_at, expected)

    # a growing set

    def test_a_second_reason_is_a_transition(self):
        subject_id = self._subject(["a"])
        self._run()
        self._subject(["a", "b"], subject_id=subject_id)
        changed, _, events = self._run()
        # the case a single-value `reasons` would have missed: the count moved, the category did not
        self.assertEqual((changed, events), (1, 1))
        self.assertEqual(self._state(subject_id).previous_reasons, ["a"])

    # recovery and unwatched subjects

    def test_recovery_deletes_the_row_and_emits(self):
        subject_id = self._subject(["a"])
        self._run()
        self._subject([], subject_id=subject_id)
        with patch.object(ProtocolTestEvent, "post") as post:
            changed, recovered, events = self._run()
        self.assertEqual((changed, recovered, events), (0, 1, 1))
        self.assertEqual(post.call_count, 1)
        self.assertFalse(
            WatchState.objects.filter(watch=self.watch.name, subject_id=subject_id).exists()
        )

    def test_a_deleted_subject_goes_unwatched_silently_without_an_incident_class(self):
        subject_id = self._subject(["a"])
        self._run()
        WatchState.objects.filter(watch="_subjects", subject_id=subject_id).delete()
        with patch.object(ProtocolTestEvent, "post") as post:
            changed, recovered, events = self._run()
        # still_watched=false: the subject left the watch's domain. That is not a recovery, and a watch
        # that opens no incident has nothing to say about it.
        self.assertEqual((changed, recovered, events), (0, 0, 0))
        self.assertEqual(post.call_count, 0)
        self.assertFalse(
            WatchState.objects.filter(watch=self.watch.name, subject_id=subject_id).exists()
        )

    # core's default emission

    def test_the_default_builds_the_framework_block_for_both_directions(self):
        watch = _FakeTriggerWatch()
        subject_id = self._subject(["a"], serial_number="SN")
        events = []
        with patch.object(ProtocolTestEvent, "post", lambda self: events.append(self)):
            with self.captureOnCommitCallbacks(execute=True):
                watch.run_once()
            self._subject([], subject_id=subject_id)
            with self.captureOnCommitCallbacks(execute=True):
                watch.run_once()
        degraded, recovered = events
        # every watch event says which watch and which subject produced it, without the reader having to
        # know one watch from another
        self.assertEqual(degraded.payload["watch"], watch.name)
        self.assertEqual(degraded.payload["subject_id"], subject_id)
        self.assertEqual(degraded.payload["status"], "degraded")
        self.assertEqual(degraded.payload["reasons"], ["a"])
        self.assertEqual(degraded.payload["previous_reasons"], [])
        self.assertGreaterEqual(degraded.payload["degraded_for"], 0)
        self.assertEqual(degraded.metadata.machine_serial_number, "SN")
        self.assertEqual(recovered.payload["status"], "recovered")
        self.assertEqual(recovered.payload["reasons"], [])
        self.assertEqual(recovered.payload["previous_reasons"], ["a"])
        # a pure trigger: no incident_class, so no incident update either way
        self.assertFalse(degraded.metadata.incident_updates)
        self.assertFalse(recovered.metadata.incident_updates)

    def test_an_unwatched_subject_closes_its_incident(self):
        watch = _FakeIncidentWatch()
        subject_id = self._subject(["a"])
        with self.captureOnCommitCallbacks(execute=True):
            watch.run_once()
        # the key was captured on insert, while the subject still existed
        self.assertEqual(
            WatchState.objects.get(watch=watch.name, subject_id=subject_id).incident_key,
            {"subject_id": subject_id},
        )
        WatchState.objects.filter(watch="_subjects", subject_id=subject_id).delete()
        with patch.object(SubjectUnwatchedEvent, "post") as post:
            with self.captureOnCommitCallbacks(execute=True):
                result = watch.run_once()
        # not a recovery — nothing was fixed — but an event IS emitted, because an incident can only be
        # closed by one, and after this tick the state row is gone for good
        self.assertEqual((result.changed, result.recovered, result.events), (0, 0, 1))
        self.assertEqual(post.call_count, 1)
        self.assertFalse(
            WatchState.objects.filter(watch=watch.name, subject_id=subject_id).exists()
        )

    def test_an_unwatched_row_closes_with_severity_none(self):
        watch = _FakeIncidentWatch()
        row = _Row(watch="_protocol_test", subject_id="x", serial_number="sn", reasons=["a"],
                   previous_reasons=[], incident_key={"subject_id": "x"}, severity=100,
                   first_fired_at=naive_utcnow())
        event = list(watch.iter_unwatched_events([row]))[0]
        update = event.metadata.incident_updates[0]
        self.assertEqual(update.incident_type, "_protocol_test_incident")
        self.assertEqual(update.key, {"subject_id": "x"})
        self.assertEqual(update.severity, Severity.NONE)
        self.assertEqual(event.metadata.machine_serial_number, "sn")
        self.assertEqual(event.payload["watch"], watch.name)
        # still degraded when it went away, so reasons stays populated — unlike a recovery
        self.assertEqual(event.payload["reasons"], ["a"])
        self.assertEqual(event.payload["previous_reasons"], [])
        self.assertIn("watch", event.tags)

    def test_an_unwatched_row_without_a_key_is_reported(self):
        # a watch that opens incidents but wrote no key leaves this one open with nothing able to close
        # it — the event still goes out, and the gap is logged rather than passed over
        watch = _FakeIncidentWatch()
        row = _Row(watch="_protocol_test", subject_id="x", serial_number=None, reasons=["a"],
                   previous_reasons=[], incident_key=None, severity=100,
                   first_fired_at=naive_utcnow())
        with self.assertLogs("zentral.core.watchers.watches", level="ERROR") as cm:
            event = list(watch.iter_unwatched_events([row]))[0]
        self.assertFalse(event.metadata.incident_updates)
        self.assertIn("no incident key on subject x", cm.output[0])

    # the transaction

    def test_a_failing_iter_events_rolls_the_state_back(self):
        subject_id = self._subject(["a"])
        with patch.object(_FakeSubjectWatch, "iter_events", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                self.watch.run_once()
        # nothing was written, so the next tick finds the transition again instead of losing it
        self.assertFalse(
            WatchState.objects.filter(watch=self.watch.name, subject_id=subject_id).exists()
        )
        changed, _, events = self._run()
        self.assertEqual((changed, events), (1, 1))

    # severity

    def test_severity_is_the_max_over_reasons(self):
        self.assertEqual(self.watch.get_severity(["a"]), 100)
        self.assertEqual(self.watch.get_severity(["a", "b"]), 300)
        self.assertIsNone(self.watch.get_severity(["unknown"]))

    def test_no_severities_means_no_severity(self):
        class _NoIncidentWatch(_FakeSubjectWatch):
            severities = {}

        self.assertIsNone(_NoIncidentWatch().get_severity(["a"]))

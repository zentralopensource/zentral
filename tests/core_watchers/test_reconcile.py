from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils.crypto import get_random_string

from zentral.core.events.base import BaseEvent
from zentral.core.incidents.models import Incident, MachineIncident, Severity, Status
from zentral.core.watchers.events import SubjectUnwatchedEvent
from zentral.core.watchers.models import WatchState
from zentral.core.watchers.watches import BaseWatch
from zentral.utils.time import naive_utcnow


class ReconcileTestEvent(BaseEvent):
    event_type = "zentral_watchers_reconcile_test"


class _TestIncident:
    incident_type = "_reconcile_test_incident"


class _GlobalWatch(BaseWatch):
    """The same standing-in trick as the protocol tests: rows tagged `_subjects` are the watched objects.

    Its subjects are not machines, so the state rows carry no serial and the incident is a plain Incident.
    """
    name = "_reconcile_test"
    interval = 1
    severities = {"a": 100}
    incident_class = _TestIncident
    event_class = ReconcileTestEvent
    machine_scoped = False

    _SUBJECT_ROWS = " FROM watchers_watchstate AS src WHERE src.watch = '_subjects'"
    _SERIAL = "NULL"

    @property
    def degraded_select(self):
        return (
            f"SELECT %(watch)s, src.subject_id, {self._SERIAL},"
            "       src.reasons, ARRAY[]::varchar[], %(severity)s,"
            "       jsonb_build_object('subject_id', src.subject_id), NOW(), NOW() "
            f"{self._SUBJECT_ROWS} AND cardinality(src.reasons) > 0"
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


class _MachineWatch(_GlobalWatch):
    "Same watch, machine scoped: the state rows carry a serial and the incident gets a MachineIncident."
    name = "_reconcile_test_machine"
    machine_scoped = True
    _SERIAL = "src.serial_number"


class _NoIncidentWatch(_GlobalWatch):
    "A watch that opens no incident has nothing to reconcile against."
    name = "_reconcile_test_no_incident"
    incident_class = None


class ReconcileTestCase(TestCase):
    # setup helpers

    def _subject(self, reasons=None, subject_id=None, serial_number=None):
        subject_id = subject_id or get_random_string(12)
        WatchState.objects.update_or_create(
            watch="_subjects", subject_id=subject_id,
            defaults={"serial_number": serial_number or get_random_string(12),
                      "reasons": reasons if reasons is not None else ["a"],
                      "severity": None,
                      "first_fired_at": naive_utcnow(),
                      "fired_at": naive_utcnow()},
        )
        return subject_id

    def _run(self, watch):
        with self.captureOnCommitCallbacks(execute=True):
            return watch.run_once()

    def _degrade(self, watch, **kwargs):
        "One full tick, then age the state row past the grace so the repair can see it."
        subject_id = self._subject(**kwargs)
        with patch.object(ReconcileTestEvent, "post"):
            self._run(watch)
        self._age(watch, subject_id)
        return subject_id

    def _age(self, watch, subject_id, seconds=None):
        WatchState.objects.filter(watch=watch.name, subject_id=subject_id).update(
            fired_at=naive_utcnow() - timedelta(seconds=seconds or watch.reconcile_grace + 60)
        )

    def _incident(self, subject_id, status=Status.OPEN, status_time=None, serial_number=None):
        incident = Incident.objects.create(
            incident_type=_TestIncident.incident_type,
            key={"subject_id": subject_id},
            severity=Severity.MAJOR.value,
            name="reconcile test",
            status=status.value,
            status_time=status_time or naive_utcnow(),
        )
        if serial_number:
            MachineIncident.objects.create(
                incident=incident, serial_number=serial_number,
                status=status.value, status_time=status_time or naive_utcnow(),
            )
        return incident

    def _collect(self, event_cls):
        events = []
        return events, patch.object(event_cls, "post", lambda self: events.append(self))

    # the forward direction: a transition with no incident to show for it

    def test_an_unreported_transition_is_re_emitted(self):
        watch = _GlobalWatch()
        subject_id = self._degrade(watch)
        events, collect = self._collect(ReconcileTestEvent)
        with collect:
            result = self._run(watch)
        self.assertEqual((result.changed, result.reconciled, result.events), (0, 1, 1))
        event = events[0]
        # the same event the first tick owed, from the same code path: only the elapsed time moved on
        self.assertEqual(event.payload["status"], "degraded")
        self.assertEqual(event.payload["subject_id"], subject_id)
        self.assertEqual(event.payload["reasons"], ["a"])
        self.assertEqual(event.payload["previous_reasons"], [])
        self.assertGreaterEqual(event.payload["degraded_for"], 0)
        update = event.metadata.incident_updates[0]
        self.assertEqual(update.key, {"subject_id": subject_id})
        self.assertEqual(update.severity, Severity(100))

    def test_an_open_incident_is_not_re_emitted(self):
        watch = _GlobalWatch()
        subject_id = self._degrade(watch)
        self._incident(subject_id)
        events, collect = self._collect(ReconcileTestEvent)
        with collect:
            result = self._run(watch)
        self.assertEqual((result.reconciled, result.events), (0, 0))
        self.assertEqual(events, [])

    def test_an_in_progress_incident_is_not_re_emitted(self):
        # somebody is working it: reported is reported, and re-announcing it helps nobody
        watch = _GlobalWatch()
        subject_id = self._degrade(watch)
        self._incident(subject_id, status=Status.IN_PROGRESS)
        self.assertEqual(self._run(watch).reconciled, 0)

    def test_a_close_after_the_transition_is_left_alone(self):
        # the deliberate close: an operator saw this degradation and resolved it
        watch = _GlobalWatch()
        subject_id = self._degrade(watch)
        fired_at = WatchState.objects.get(watch=watch.name, subject_id=subject_id).fired_at
        self._incident(subject_id, status=Status.CLOSED, status_time=fired_at + timedelta(seconds=1))
        self.assertEqual(self._run(watch).reconciled, 0)

    def test_a_close_before_the_transition_is_re_emitted(self):
        # a close that belongs to an EARLIER degradation says nothing about this one
        watch = _GlobalWatch()
        subject_id = self._degrade(watch)
        fired_at = WatchState.objects.get(watch=watch.name, subject_id=subject_id).fired_at
        self._incident(subject_id, status=Status.CLOSED, status_time=fired_at - timedelta(seconds=1))
        with patch.object(ReconcileTestEvent, "post"):
            self.assertEqual(self._run(watch).reconciled, 1)

    def test_a_transition_inside_the_grace_is_not_re_emitted(self):
        # the events of a tick are posted after its commit, so everything is briefly unreported
        watch = _GlobalWatch()
        subject_id = self._subject()
        with patch.object(ReconcileTestEvent, "post"):
            first = self._run(watch)
            second = self._run(watch)
        self.assertEqual((first.changed, first.events), (1, 1))
        self.assertEqual((second.changed, second.reconciled, second.events), (0, 0, 0))
        self.assertTrue(WatchState.objects.filter(watch=watch.name, subject_id=subject_id).exists())

    def test_a_row_without_an_incident_key_is_not_re_emitted(self):
        # nothing to match against, and re-emitting it every tick would never converge
        watch = _GlobalWatch()
        subject_id = self._degrade(watch)
        WatchState.objects.filter(watch=watch.name, subject_id=subject_id).update(incident_key=None)
        self.assertEqual(self._run(watch).reconciled, 0)

    def test_a_watch_without_an_incident_class_does_not_reconcile(self):
        watch = _NoIncidentWatch()
        self._degrade(watch)
        self.assertEqual((self._run(watch).reconciled, self._run(watch).closed), (0, 0))

    def test_a_null_grace_disables_the_repair(self):
        watch = _GlobalWatch()
        subject_id = self._degrade(watch)
        watch.reconcile_grace = None
        self.assertEqual(self._run(watch).reconciled, 0)
        self.assertTrue(WatchState.objects.filter(watch=watch.name, subject_id=subject_id).exists())

    # the forward direction, machine scoped

    def test_a_machine_incident_missing_for_one_serial_is_re_emitted(self):
        # the shape the inventory watch has: the parent incident is open for another machine entirely, so
        # only the machine incident says whether THIS subject was reported
        watch = _MachineWatch()
        subject_id = self._degrade(watch, serial_number="SN1")
        self._incident(subject_id)
        events, collect = self._collect(ReconcileTestEvent)
        with collect:
            self.assertEqual(self._run(watch).reconciled, 1)
        self.assertEqual(events[0].metadata.machine_serial_number, "SN1")

    def test_an_open_machine_incident_is_not_re_emitted(self):
        watch = _MachineWatch()
        subject_id = self._degrade(watch, serial_number="SN1")
        self._incident(subject_id, serial_number="SN1")
        self.assertEqual(self._run(watch).reconciled, 0)

    # the reverse direction: an incident with no transition left to close it

    def test_an_orphaned_incident_is_closed(self):
        watch = _GlobalWatch()
        subject_id = get_random_string(12)
        self._incident(subject_id, status_time=naive_utcnow() - timedelta(seconds=watch.reconcile_grace + 60))
        events, collect = self._collect(SubjectUnwatchedEvent)
        with collect:
            result = self._run(watch)
        self.assertEqual((result.closed, result.events), (1, 1))
        event = events[0]
        self.assertEqual(event.payload["status"], "unwatched")
        self.assertEqual(event.payload["watch"], watch.name)
        # the row is gone, so these cannot be recovered — and are not invented
        self.assertIsNone(event.payload["subject_id"])
        self.assertEqual(event.payload["reasons"], [])
        update = event.metadata.incident_updates[0]
        self.assertEqual(update.key, {"subject_id": subject_id})
        self.assertEqual(update.severity, Severity.NONE)

    def test_an_orphaned_machine_incident_is_closed(self):
        watch = _MachineWatch()
        subject_id = get_random_string(12)
        old = naive_utcnow() - timedelta(seconds=watch.reconcile_grace + 60)
        self._incident(subject_id, status_time=old, serial_number="SN1")
        events, collect = self._collect(SubjectUnwatchedEvent)
        with collect:
            self.assertEqual(self._run(watch).closed, 1)
        # one event per orphaned machine incident and none for the parent: close_open_incident holds the
        # parent open until the last machine incident closes, then closes it
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].metadata.machine_serial_number, "SN1")

    def test_an_incident_with_a_state_row_is_not_closed(self):
        watch = _GlobalWatch()
        subject_id = self._degrade(watch)
        self._incident(subject_id, status_time=naive_utcnow() - timedelta(seconds=watch.reconcile_grace + 60))
        self.assertEqual(self._run(watch).closed, 0)

    def test_an_incident_closed_on_this_tick_is_not_closed_twice(self):
        # status_time is the time the incident was OPENED, so the grace window does not separate a close
        # that is still in flight — the rows deleted on this tick have to be excluded by identity
        watch = _GlobalWatch()
        subject_id = self._degrade(watch)
        self._incident(subject_id, status_time=naive_utcnow() - timedelta(seconds=watch.reconcile_grace + 60))
        self._subject(reasons=[], subject_id=subject_id)
        events, collect = self._collect(ReconcileTestEvent)
        with collect:
            result = self._run(watch)
        # the recovery closes it, and the repair does not say so a second time
        self.assertEqual((result.recovered, result.closed, result.events), (1, 0, 1))

    def test_an_orphaned_incident_inside_the_grace_is_not_closed(self):
        watch = _GlobalWatch()
        self._incident(get_random_string(12))
        self.assertEqual(self._run(watch).closed, 0)

    def test_only_open_incidents_are_closed(self):
        # close_open_incident refuses anything but OPEN, so an event about the others changes nothing
        watch = _GlobalWatch()
        old = naive_utcnow() - timedelta(seconds=watch.reconcile_grace + 60)
        for status in (Status.IN_PROGRESS, Status.REOPENED, Status.CLOSED, Status.RESOLVED):
            self._incident(get_random_string(12), status=status, status_time=old)
        self.assertEqual(self._run(watch).closed, 0)

    def test_another_watch_incident_type_is_left_alone(self):
        watch = _GlobalWatch()
        incident = self._incident(get_random_string(12),
                                  status_time=naive_utcnow() - timedelta(seconds=watch.reconcile_grace + 60))
        Incident.objects.filter(pk=incident.pk).update(incident_type="somebody_elses_incident")
        self.assertEqual(self._run(watch).closed, 0)

    # visibility

    def test_the_repair_is_logged_as_a_warning(self):
        watch = _GlobalWatch()
        self._degrade(watch)
        with patch.object(ReconcileTestEvent, "post"):
            with self.assertLogs("zentral.core.watchers.watches", level="WARNING") as cm:
                self._run(watch)
        self.assertIn("re-emitted 1 transition(s), closed 0 incident(s)", cm.output[0])

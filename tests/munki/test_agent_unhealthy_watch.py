from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils.crypto import get_random_string

from zentral.contrib.munki.events import MunkiAgentHealthEvent
from zentral.contrib.munki.incidents import MunkiAgentUnhealthyIncident
from zentral.contrib.munki.models import MunkiState
from zentral.contrib.munki.watches import MunkiAgentUnhealthyWatch
from zentral.core.incidents.models import Severity
from zentral.core.watchers.events import SubjectUnwatchedEvent
from zentral.core.watchers.models import WatchState
from zentral.utils.time import naive_utcnow


class MunkiAgentUnhealthyWatchTestCase(TestCase):
    def setUp(self):
        self.watch = MunkiAgentUnhealthyWatch()

    # utility methods

    def _force_munki_state(self, preflight_days_ago=0, postflight_days_ago=0, age_days=30):
        """age_days is how long ago the row was created — the onboarding grace measures against it."""
        now = naive_utcnow()
        munki_state = MunkiState.objects.create(
            machine_serial_number=get_random_string(12),
            user_agent="Zentral/munkipostflight 0.14",
        )
        MunkiState.objects.filter(pk=munki_state.pk).update(
            created_at=now - timedelta(days=age_days),
            last_preflight_at=None if preflight_days_ago is None else now - timedelta(days=preflight_days_ago),
            last_postflight_at=None if postflight_days_ago is None else now - timedelta(days=postflight_days_ago),
        )
        munki_state.refresh_from_db()
        return munki_state

    def _state(self, munki_state):
        return WatchState.objects.get(watch=self.watch.name, subject_id=str(munki_state.pk))

    def _run(self):
        with self.captureOnCommitCallbacks(execute=True):
            return self.watch.run_once()

    def _collect(self, event_cls=MunkiAgentHealthEvent):
        events = []
        return events, patch.object(event_cls, "post", lambda self: events.append(self))

    # healthy

    def test_a_healthy_machine_is_not_reported(self):
        munki_state = self._force_munki_state(preflight_days_ago=0, postflight_days_ago=0)
        self.assertEqual(self._run(), (0, 0, 0))
        self.assertFalse(WatchState.objects.filter(subject_id=str(munki_state.pk)).exists())

    def test_just_inside_the_period_is_healthy(self):
        self._force_munki_state(preflight_days_ago=6, postflight_days_ago=6)
        self.assertEqual(self._run(), (0, 0, 0))

    # the onboarding grace

    def test_a_freshly_enrolled_machine_is_not_reported(self):
        # the preflight creates the row, so without the grace every machine would read never_completed
        # for the minutes between its first poll and its first completed run
        munki_state = self._force_munki_state(preflight_days_ago=0, postflight_days_ago=None, age_days=0)
        self.assertEqual(self._run(), (0, 0, 0))
        self.assertFalse(WatchState.objects.filter(subject_id=str(munki_state.pk)).exists())

    def test_the_grace_expires(self):
        munki_state = self._force_munki_state(preflight_days_ago=0, postflight_days_ago=None, age_days=2)
        self.assertEqual(self._run()[0], 1)
        self.assertEqual(self._state(munki_state).reasons, ["never_completed"])

    # the four contact reasons

    def test_never_onboarded(self):
        munki_state = self._force_munki_state(preflight_days_ago=None, postflight_days_ago=None)
        self._run()
        state = self._state(munki_state)
        self.assertEqual(state.reasons, ["never_onboarded"])
        self.assertEqual(state.severity, Severity.MINOR.value)
        self.assertEqual(state.serial_number, munki_state.machine_serial_number)

    def test_gone(self):
        munki_state = self._force_munki_state(preflight_days_ago=10, postflight_days_ago=10)
        self._run()
        state = self._state(munki_state)
        self.assertEqual(state.reasons, ["gone"])
        self.assertEqual(state.severity, Severity.MAJOR.value)

    def test_never_completed(self):
        # polling, but never once finished a run — the population that is invisible without the split
        munki_state = self._force_munki_state(preflight_days_ago=0, postflight_days_ago=None)
        self._run()
        self.assertEqual(self._state(munki_state).reasons, ["never_completed"])

    def test_stopped_completing(self):
        # still polling every cycle, so it looks alive by every other signal
        munki_state = self._force_munki_state(preflight_days_ago=0, postflight_days_ago=10)
        self._run()
        self.assertEqual(self._state(munki_state).reasons, ["stopped_completing"])

    def test_the_reasons_are_mutually_exclusive_first_match(self):
        # both preflight and postflight stale: `gone` wins, because it is the more fundamental diagnosis
        munki_state = self._force_munki_state(preflight_days_ago=10, postflight_days_ago=20)
        self._run()
        self.assertEqual(self._state(munki_state).reasons, ["gone"])

    # transitions

    def test_a_changed_diagnosis_carries_the_previous_one(self):
        munki_state = self._force_munki_state(preflight_days_ago=0, postflight_days_ago=10)
        self._run()
        self.assertEqual(self._state(munki_state).reasons, ["stopped_completing"])
        MunkiState.objects.filter(pk=munki_state.pk).update(
            last_preflight_at=naive_utcnow() - timedelta(days=10)
        )
        events, ctx = self._collect()
        with ctx:
            changed, _, event_count = self._run()
        self.assertEqual((changed, event_count), (1, 1))
        state = self._state(munki_state)
        self.assertEqual(state.reasons, ["gone"])
        self.assertEqual(state.previous_reasons, ["stopped_completing"])
        # same event type in both directions: `status` is what tells them apart
        self.assertEqual(events[0].payload["status"], "degraded")
        self.assertEqual(events[0].payload["reasons"], ["gone"])
        self.assertEqual(events[0].payload["previous_reasons"], ["stopped_completing"])
        self.assertIn("watch", events[0].tags)
        # machine-scoped: the serial on the metadata makes this a MachineIncident
        self.assertEqual(events[0].metadata.machine_serial_number, munki_state.machine_serial_number)
        incident_update = events[0].metadata.incident_updates[0]
        self.assertEqual(incident_update.incident_type, "munki_agent_unhealthy")
        # the reason is NOT in the key, or a change of diagnosis would open a second incident
        self.assertEqual(incident_update.key, {"munki_msn": munki_state.machine_serial_number})

    def test_an_unchanged_diagnosis_emits_nothing(self):
        munki_state = self._force_munki_state(preflight_days_ago=10, postflight_days_ago=10)
        self._run()
        MunkiState.objects.filter(pk=munki_state.pk).update(
            last_preflight_at=naive_utcnow() - timedelta(days=11)
        )
        with patch.object(MunkiAgentHealthEvent, "post") as post:
            self.assertEqual(self._run(), (0, 0, 0))
        self.assertEqual(post.call_count, 0)

    def test_the_first_report_has_no_previous_reason(self):
        self._force_munki_state(preflight_days_ago=10, postflight_days_ago=10)
        events, ctx = self._collect()
        with ctx:
            self._run()
        # the shape never varies: no previous conclusion is an empty array, not a null
        self.assertEqual(events[0].payload["previous_reasons"], [])

    # recovery

    def test_a_machine_that_reports_again_recovers(self):
        munki_state = self._force_munki_state(preflight_days_ago=10, postflight_days_ago=10)
        self._run()
        MunkiState.objects.filter(pk=munki_state.pk).update(
            last_preflight_at=naive_utcnow(), last_postflight_at=naive_utcnow()
        )
        events, ctx = self._collect(MunkiAgentHealthEvent)
        with ctx:
            changed, recovered, event_count = self._run()
        self.assertEqual((changed, recovered, event_count), (0, 1, 1))
        self.assertFalse(WatchState.objects.filter(watch=self.watch.name,
                                                   subject_id=str(munki_state.pk)).exists())
        self.assertEqual(events[0].payload["status"], "recovered")
        self.assertEqual(events[0].payload["previous_reasons"], ["gone"])
        # healthy is the empty array, which the sparse table never stores
        self.assertEqual(events[0].payload["reasons"], [])
        self.assertEqual(events[0].metadata.incident_updates[0].severity, Severity.NONE)
        self.assertEqual(events[0].metadata.machine_serial_number, munki_state.machine_serial_number)

    def test_a_deleted_munki_state_closes_its_incident_without_healing(self):
        munki_state = self._force_munki_state(preflight_days_ago=10, postflight_days_ago=10)
        self._run()
        pk = munki_state.pk
        serial_number = munki_state.machine_serial_number
        munki_state.delete()
        unwatched = []
        with patch.object(MunkiAgentHealthEvent, "post") as healthy_post:
            with patch.object(SubjectUnwatchedEvent, "post",
                              lambda self: unwatched.append(self)):
                changed, recovered, events = self._run()
        # the agent did not become healthy, the machine left munki — but its incident is still closed
        self.assertEqual((changed, recovered, events), (0, 0, 1))
        self.assertEqual(healthy_post.call_count, 0)
        self.assertFalse(WatchState.objects.filter(watch=self.watch.name, subject_id=str(pk)).exists())
        incident_update = unwatched[0].metadata.incident_updates[0]
        self.assertEqual(incident_update.incident_type, MunkiAgentUnhealthyIncident.incident_type)
        self.assertEqual(incident_update.key, {"munki_msn": serial_number})
        self.assertEqual(incident_update.severity, Severity.NONE)
        self.assertEqual(unwatched[0].metadata.machine_serial_number, serial_number)

    # the ladder is one source of truth

    def test_severities_are_derived_from_the_ladder(self):
        self.assertEqual(
            self.watch.severities,
            {"never_onboarded": Severity.MINOR.value,
             "gone": Severity.MAJOR.value,
             "never_completed": Severity.MAJOR.value,
             "stopped_completing": Severity.MAJOR.value},
        )

    def test_updated_at_is_never_used(self):
        # updated_at is auto_now, so force_full_sync() moves it: keying on it would report a long-dead
        # machine as healthy the moment an admin touched it
        sql = self.watch.degraded_select + self.watch.still_degraded
        self.assertNotIn("updated_at", sql)

    # incident class

    def test_incident_get_objects_and_name(self):
        munki_state = self._force_munki_state()
        serial_number = munki_state.machine_serial_number
        incident = MunkiAgentUnhealthyIncident(
            type("I", (), {"key": MunkiAgentUnhealthyIncident.get_incident_key(serial_number),
                           "pk": 1})()
        )
        self.assertEqual(incident.get_objects(), [munki_state])
        self.assertEqual(incident.get_name(),
                         f"Munki agent on {serial_number} is not completing runs")
        display = list(incident.get_objects_for_display())
        self.assertEqual(display[0][0], "Munki state")
        self.assertEqual(display[0][2], [munki_state])

    def test_incident_with_an_unknown_machine(self):
        incident = MunkiAgentUnhealthyIncident(
            type("I", (), {"key": {"munki_msn": "does-not-exist"}, "pk": 1})()
        )
        self.assertEqual(incident.get_objects(), [])
        self.assertEqual(list(incident.get_objects_for_display()), [])

    def test_incident_with_a_malformed_key(self):
        incident = MunkiAgentUnhealthyIncident(type("I", (), {"key": {"yolo": "fomo"}, "pk": 1})())
        self.assertEqual(incident.get_objects(), [])
        self.assertEqual(incident.get_name(), "Unknown machine munki agent is unhealthy")

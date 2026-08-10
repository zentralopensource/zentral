from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils.crypto import get_random_string

from zentral.contrib.mdm.events import PushCertificateHealthEvent
from zentral.contrib.mdm.incidents import PushCertificateExpiryIncident
from zentral.contrib.mdm.models import PushCertificate
from zentral.contrib.mdm.watches import PushCertificateExpiryWatch
from zentral.core.incidents.models import Severity
from zentral.core.watchers.events import SubjectUnwatchedEvent
from zentral.core.watchers.models import WatchState
from zentral.utils.time import naive_utcnow


class PushCertificateExpiryWatchTestCase(TestCase):
    def setUp(self):
        self.watch = PushCertificateExpiryWatch()

    # utility methods

    def _force_push_certificate(self, days_to_expiry=None):
        not_after = None
        if days_to_expiry is not None:
            not_after = naive_utcnow() + timedelta(days=days_to_expiry)
        return PushCertificate.objects.create(
            name=get_random_string(12),
            topic=get_random_string(12),
            not_before=naive_utcnow() - timedelta(days=365),
            not_after=not_after,
        )

    def _expire_in(self, push_certificate, days):
        PushCertificate.objects.filter(pk=push_certificate.pk).update(
            not_after=naive_utcnow() + timedelta(days=days)
        )

    def _state(self, push_certificate):
        return WatchState.objects.get(watch=self.watch.name, subject_id=str(push_certificate.pk))

    def _run(self):
        with self.captureOnCommitCallbacks(execute=True):
            return self.watch.run_once()

    def _collect(self, event_cls=PushCertificateHealthEvent):
        events = []
        return events, patch.object(event_cls, "post", lambda self: events.append(self))

    # nothing to report

    def test_a_distant_expiry_is_not_reported(self):
        self._force_push_certificate(days_to_expiry=200)
        self.assertEqual(self._run(), (0, 0, 0))

    def test_a_certificate_without_an_expiry_is_not_reported(self):
        # not provisioned yet: there is no deadline to warn about
        pc = self._force_push_certificate()
        self.assertIsNone(pc.not_after)
        self.assertEqual(self._run(), (0, 0, 0))
        self.assertFalse(WatchState.objects.filter(subject_id=str(pc.pk)).exists())

    # the ladder

    def test_each_rung_of_the_ladder(self):
        for days, reason, severity in ((80, "expiring_90d", Severity.MINOR),
                                       (20, "expiring_30d", Severity.MAJOR),
                                       (3, "expiring_7d", Severity.CRITICAL),
                                       (-1, "expired", Severity.CRITICAL)):
            with self.subTest(reason=reason):
                pc = self._force_push_certificate(days_to_expiry=days)
                self._run()
                state = self._state(pc)
                self.assertEqual(state.reasons, [reason])
                self.assertEqual(state.severity, severity.value)
                # push certificates are not machine-scoped: one serves the whole fleet
                self.assertIsNone(state.serial_number)

    def test_the_ladder_ratchets_and_carries_the_previous_rung(self):
        pc = self._force_push_certificate(days_to_expiry=80)
        self._run()
        self.assertEqual(self._state(pc).reasons, ["expiring_90d"])
        self._expire_in(pc, 20)
        events, ctx = self._collect()
        with ctx:
            changed, _, event_count = self._run()
        self.assertEqual((changed, event_count), (1, 1))
        state = self._state(pc)
        self.assertEqual(state.reasons, ["expiring_30d"])
        self.assertEqual(state.previous_reasons, ["expiring_90d"])
        # the payload names both sides, so the event says "90 days -> 30 days", not just "expiring"
        # same event type as the renewal below: `status` is what tells them apart
        self.assertEqual(events[0].payload["status"], "degraded")
        self.assertEqual(events[0].payload["reasons"], ["expiring_30d"])
        self.assertEqual(events[0].payload["previous_reasons"], ["expiring_90d"])
        self.assertIn("watch", events[0].tags)
        self.assertEqual(events[0].payload["push_certificate"]["pk"], pc.pk)
        # linked to the certificate, so it lands on that certificate's event page
        self.assertEqual(events[0].get_linked_objects_keys(), {"mdm_push_certificate": [(pc.pk,)]})
        self.assertEqual(events[0].payload["push_certificate"]["name"], pc.name)
        # no machine on the metadata ⇒ a plain Incident, not a MachineIncident
        self.assertIsNone(events[0].metadata.machine_serial_number)

    def test_staying_on_the_same_rung_emits_nothing(self):
        pc = self._force_push_certificate(days_to_expiry=80)
        self._run()
        self._expire_in(pc, 75)   # still in the 90d band
        with patch.object(PushCertificateHealthEvent, "post") as post:
            self.assertEqual(self._run(), (0, 0, 0))
        self.assertEqual(post.call_count, 0)

    def test_the_first_report_has_no_previous_reason(self):
        self._force_push_certificate(days_to_expiry=3)
        events, ctx = self._collect()
        with ctx:
            self._run()
        # the shape never varies: no previous conclusion is an empty array, not a null
        self.assertEqual(events[0].payload["previous_reasons"], [])

    def test_incident_severity_rises_with_the_rung(self):
        pc = self._force_push_certificate(days_to_expiry=80)
        events, ctx = self._collect()
        with ctx:
            self._run()
            self._expire_in(pc, 3)
            self._run()
        self.assertEqual(events[0].metadata.incident_updates[0].severity, Severity.MINOR)
        self.assertEqual(events[1].metadata.incident_updates[0].severity, Severity.CRITICAL)
        self.assertEqual(events[1].metadata.incident_updates[0].key, {"mdm_pc_pk": pc.pk})

    # renewal

    def test_renewal_closes_the_incident(self):
        pc = self._force_push_certificate(days_to_expiry=3)
        self._run()
        self._expire_in(pc, 400)   # renewed
        events, ctx = self._collect(PushCertificateHealthEvent)
        with ctx:
            changed, recovered, event_count = self._run()
        self.assertEqual((changed, recovered, event_count), (0, 1, 1))
        self.assertFalse(WatchState.objects.filter(watch=self.watch.name,
                                                   subject_id=str(pc.pk)).exists())
        self.assertEqual(events[0].payload["status"], "recovered")
        self.assertEqual(events[0].payload["previous_reasons"], ["expiring_7d"])
        # renewed is the empty array, which the sparse table never stores
        self.assertEqual(events[0].payload["reasons"], [])
        self.assertEqual(events[0].metadata.incident_updates[0].severity, Severity.NONE)

    def test_a_cleared_expiry_recovers_with_a_null_not_after(self):
        pc = self._force_push_certificate(days_to_expiry=3)
        self._run()
        PushCertificate.objects.filter(pk=pc.pk).update(not_after=None)
        events, ctx = self._collect(PushCertificateHealthEvent)
        with ctx:
            _, recovered, _ = self._run()
        self.assertEqual(recovered, 1)
        self.assertIsNone(events[0].payload["push_certificate"]["not_after"])

    def test_a_deleted_certificate_closes_its_incident_without_renewing(self):
        pc = self._force_push_certificate(days_to_expiry=3)
        self._run()
        pk = pc.pk
        pc.delete()
        unwatched = []
        with patch.object(PushCertificateHealthEvent, "post") as renewed_post:
            with patch.object(SubjectUnwatchedEvent, "post",
                              lambda self: unwatched.append(self)):
                changed, recovered, events = self._run()
        # deleting a certificate is not renewing one, so no renewal event — but the incident must not be
        # left open on a certificate that no longer exists
        self.assertEqual((changed, recovered, events), (0, 0, 1))
        self.assertEqual(renewed_post.call_count, 0)
        self.assertFalse(WatchState.objects.filter(watch=self.watch.name, subject_id=str(pk)).exists())
        incident_update = unwatched[0].metadata.incident_updates[0]
        self.assertEqual(incident_update.incident_type, PushCertificateExpiryIncident.incident_type)
        self.assertEqual(incident_update.key, {"mdm_pc_pk": pk})
        self.assertEqual(incident_update.severity, Severity.NONE)
        # not a machine incident: one certificate serves the whole fleet
        self.assertIsNone(unwatched[0].metadata.machine_serial_number)
        # NOT linked: the certificate is deleted, so there is no page for the link to land on
        self.assertEqual(unwatched[0].metadata.objects, {})

    # the ladder is one source of truth

    def test_severities_are_derived_from_the_ladder(self):
        self.assertEqual(
            self.watch.severities,
            {"expired": Severity.CRITICAL.value,
             "expiring_7d": Severity.CRITICAL.value,
             "expiring_30d": Severity.MAJOR.value,
             "expiring_90d": Severity.MINOR.value},
        )

    # a certificate deleted between the statements and the lookup: the statements ran under READ
    # COMMITTED, so a concurrent delete can land before iter_events reads the row back

    def _vanished(self):
        return patch.object(PushCertificateExpiryWatch, "get_subjects", return_value={})

    def test_a_vanished_certificate_still_emits_on_degradation(self):
        pc = self._force_push_certificate(days_to_expiry=3)
        events, ctx = self._collect()
        with self._vanished():
            with ctx:
                changed, _, event_count = self._run()
        # the transition happened, so it is reported — the subject block is null and the incident update
        # comes from the row's stored key, which does not need the lookup to have succeeded
        self.assertEqual((changed, event_count), (1, 1))
        self.assertIsNone(events[0].payload["push_certificate"])
        self.assertEqual(events[0].payload["reasons"], ["expiring_7d"])
        self.assertEqual(events[0].metadata.incident_updates[0].key, {"mdm_pc_pk": pc.pk})
        # nothing to link to without the subject block
        self.assertEqual(events[0].get_linked_objects_keys(), {})

    def test_a_vanished_certificate_still_emits_on_recovery(self):
        pc = self._force_push_certificate(days_to_expiry=3)
        self._run()
        self._expire_in(pc, 400)
        events, ctx = self._collect()
        with self._vanished():
            with ctx:
                _, recovered, event_count = self._run()
        self.assertEqual((recovered, event_count), (1, 1))
        self.assertEqual(events[0].payload["status"], "recovered")
        self.assertEqual(events[0].metadata.incident_updates[0].severity, Severity.NONE)

    # incident class

    def test_incident_get_objects_and_name(self):
        pc = self._force_push_certificate(days_to_expiry=3)
        incident = PushCertificateExpiryIncident(
            type("I", (), {"key": PushCertificateExpiryIncident.get_incident_key(pc.pk), "pk": 1})()
        )
        self.assertEqual(incident.get_objects(), [pc])
        self.assertEqual(incident.get_name(), f"MDM push certificate {pc.name} is expiring")
        display = list(incident.get_objects_for_display())
        self.assertEqual(display[0][0], "MDM push certificate")
        self.assertEqual(display[0][2], [pc])

    def test_incident_with_an_unknown_certificate(self):
        incident = PushCertificateExpiryIncident(
            type("I", (), {"key": {"mdm_pc_pk": 1234567}, "pk": 1})()
        )
        self.assertEqual(incident.get_objects(), [])
        self.assertEqual(incident.get_name(), "Unknown MDM push certificate is expiring")
        self.assertEqual(list(incident.get_objects_for_display()), [])

    def test_incident_with_a_malformed_key(self):
        incident = PushCertificateExpiryIncident(type("I", (), {"key": {"yolo": "fomo"}, "pk": 1})())
        self.assertEqual(incident.get_objects(), [])

import hashlib
import json
import uuid
from unittest.mock import patch
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MachineTag, Tag
from zentral.contrib.turbo.events import TurboEnrollmentEvent
from zentral.contrib.turbo.models import EnrolledMachine, OneTimeJobMachine, RecurringJobMachine
from zentral.core.compliance_checks.models import MachineStatus, Status
from django.utils import timezone
from .utils import (TurboPublicTestCase, force_enrollment, force_one_time_job, force_recurring_job,
                    force_script)


class TurboEnrollPublicTestCase(TurboPublicTestCase):
    def _enroll(self, enrollment, serial_number, hardware_uuid=None, secret=None):
        return self.client.post(
            reverse("turbo_public:enroll"),
            data=json.dumps({
                "secret": secret if secret is not None else enrollment.secret.secret,
                "serial_number": serial_number,
                "hardware_uuid": hardware_uuid or str(uuid.uuid4()),
            }),
            content_type="application/json",
        )

    def test_enroll_bad_secret(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        response = self._enroll(enrollment, get_random_string(12), secret="not-a-real-secret")
        self.assertEqual(response.status_code, 400)
        # same opaque code as a malformed body — a caller must not learn why the secret was refused
        self.assertEqual(response.json(), {"error": "invalid_enrollment"})

    def test_enroll_missing_field(self):
        response = self.client.post(
            reverse("turbo_public:enroll"),
            data=json.dumps({"serial_number": get_random_string(12)}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "invalid_enrollment"})

    def test_enroll_invalid_json(self):
        response = self.client.post(reverse("turbo_public:enroll"), data="not json",
                                    content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "invalid_json"})

    def test_enroll_oversized_serial_number(self):
        # the wire enroll fields are length-bounded so absurd input never reaches the DB or the
        # inventory/event pipeline
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        response = self._enroll(enrollment, "A" * 257)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "invalid_enrollment"})
        self.assertEqual(EnrolledMachine.objects.count(), 0)

    def test_enroll_non_object_body(self):
        for body in ("[]", '"abc"'):
            response = self.client.post(reverse("turbo_public:enroll"), data=body,
                                        content_type="application/json")
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json(), {"error": "invalid_json"})

    def test_enroll_non_string_field(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        response = self.client.post(
            reverse("turbo_public:enroll"),
            data=json.dumps({"secret": enrollment.secret.secret,
                             "serial_number": ["not", "a", "string"],
                             "hardware_uuid": str(uuid.uuid4())}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "invalid_enrollment"})

    def test_enroll(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        serial_number = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True):
            response = self._enroll(enrollment, serial_number)
        self.assertEqual(response.status_code, 200)
        token = response.json()["token"]
        self.assertEqual(len(token), 64)
        em = EnrolledMachine.objects.get(enrollment=enrollment, serial_number=serial_number)
        # only the sha256 of the token is stored
        self.assertEqual(em.token_hash, hashlib.sha256(token.encode("utf-8")).hexdigest())

    def test_enroll_applies_tags(self):
        tag = Tag.objects.create(name=get_random_string(12))
        enrollment = force_enrollment(meta_business_unit=self.mbu, tags=[tag])
        serial_number = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True):
            self._enroll(enrollment, serial_number)
        self.assertTrue(MachineTag.objects.filter(serial_number=serial_number, tag=tag).exists())

    def test_re_enrollment_rotates_token(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        serial_number = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True):
            token1 = self._enroll(enrollment, serial_number).json()["token"]
        with self.captureOnCommitCallbacks(execute=True):
            token2 = self._enroll(enrollment, serial_number).json()["token"]
        self.assertNotEqual(token1, token2)
        self.assertEqual(
            EnrolledMachine.objects.filter(enrollment=enrollment, serial_number=serial_number).count(), 1)
        em = EnrolledMachine.objects.get(enrollment=enrollment, serial_number=serial_number)
        self.assertEqual(em.token_hash, hashlib.sha256(token2.encode("utf-8")).hexdigest())

    def test_re_home_to_new_configuration_drops_ledger(self):
        enrollment_a = force_enrollment(meta_business_unit=self.mbu)
        serial_number = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True):
            self._enroll(enrollment_a, serial_number)
        recurring_job = force_recurring_job(configuration=enrollment_a.configuration)
        one_time_job = force_one_time_job(configuration=enrollment_a.configuration)
        RecurringJobMachine.objects.create(serial_number=serial_number, recurring_job=recurring_job)
        OneTimeJobMachine.objects.create(serial_number=serial_number, one_time_job=one_time_job)
        # re-enrolling into the same enrollment keeps the trackers (both tables)
        with self.captureOnCommitCallbacks(execute=True):
            self._enroll(enrollment_a, serial_number)
        self.assertEqual(RecurringJobMachine.objects.filter(serial_number=serial_number).count(), 1)
        self.assertEqual(OneTimeJobMachine.objects.filter(serial_number=serial_number).count(), 1)
        # enrolling into a different configuration drops them
        enrollment_b = force_enrollment(meta_business_unit=self.mbu)
        with self.captureOnCommitCallbacks(execute=True):
            self._enroll(enrollment_b, serial_number)
        self.assertEqual(RecurringJobMachine.objects.filter(serial_number=serial_number).count(), 0)
        self.assertEqual(OneTimeJobMachine.objects.filter(serial_number=serial_number).count(), 0)

    def test_re_home_to_new_configuration_drops_compliance_statuses(self):
        enrollment_a = force_enrollment(meta_business_unit=self.mbu)
        serial_number = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True):
            self._enroll(enrollment_a, serial_number)
        script = force_script(compliance_check=True)
        MachineStatus.objects.create(
            compliance_check=script.compliance_check,
            compliance_check_version=script.job.version,
            serial_number=serial_number, status=Status.OK.value, status_time=timezone.now())
        # enrolling into a different configuration drops the stale compliance status
        enrollment_b = force_enrollment(meta_business_unit=self.mbu)
        with self.captureOnCommitCallbacks(execute=True):
            self._enroll(enrollment_b, serial_number)
        self.assertFalse(MachineStatus.objects.filter(
            compliance_check=script.compliance_check, serial_number=serial_number).exists())

    def test_re_home_deletes_superseded_enrolled_machine_and_token(self):
        enrollment_a = force_enrollment(meta_business_unit=self.mbu)
        serial_number = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True):
            token_a = self._enroll(enrollment_a, serial_number).json()["token"]
        enrollment_b = force_enrollment(meta_business_unit=self.mbu)
        with self.captureOnCommitCallbacks(execute=True):
            self._enroll(enrollment_b, serial_number)
        # the superseded row is gone, and with it the old token
        self.assertEqual(EnrolledMachine.objects.filter(serial_number=serial_number).count(), 1)
        self.assertEqual(
            EnrolledMachine.objects.get(serial_number=serial_number).enrollment, enrollment_b)
        response = self.client.get(reverse("turbo_public:config"),
                                   HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token_a}")
        self.assertEqual(response.status_code, 401)

    def test_re_home_back_drops_intermediate_ledger(self):
        # A → B → A: the second re-home must drop B's ledger and compliance state too
        enrollment_a = force_enrollment(meta_business_unit=self.mbu)
        enrollment_b = force_enrollment(meta_business_unit=self.mbu)
        serial_number = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True):
            self._enroll(enrollment_a, serial_number)
        with self.captureOnCommitCallbacks(execute=True):
            self._enroll(enrollment_b, serial_number)
        recurring_job = force_recurring_job(configuration=enrollment_b.configuration)
        RecurringJobMachine.objects.create(serial_number=serial_number, recurring_job=recurring_job)
        script = force_script(compliance_check=True)
        MachineStatus.objects.create(
            compliance_check=script.compliance_check,
            compliance_check_version=script.job.version,
            serial_number=serial_number, status=Status.OK.value, status_time=timezone.now())
        with self.captureOnCommitCallbacks(execute=True):
            self._enroll(enrollment_a, serial_number)
        self.assertEqual(RecurringJobMachine.objects.filter(serial_number=serial_number).count(), 0)
        self.assertFalse(MachineStatus.objects.filter(serial_number=serial_number).exists())
        self.assertEqual(EnrolledMachine.objects.filter(serial_number=serial_number).count(), 1)
        self.assertEqual(
            EnrolledMachine.objects.get(serial_number=serial_number).enrollment, enrollment_a)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_second_enrollment_same_configuration_supersedes_row_keeps_ledger(self, post_event):
        enrollment_1 = force_enrollment(meta_business_unit=self.mbu)
        enrollment_2 = force_enrollment(configuration=enrollment_1.configuration)
        serial_number = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True):
            self._enroll(enrollment_1, serial_number)
        recurring_job = force_recurring_job(configuration=enrollment_1.configuration)
        RecurringJobMachine.objects.create(serial_number=serial_number, recurring_job=recurring_job)
        with self.captureOnCommitCallbacks(execute=True):
            self._enroll(enrollment_2, serial_number)
        # same configuration: the old row is superseded but the trackers stay
        self.assertEqual(EnrolledMachine.objects.filter(serial_number=serial_number).count(), 1)
        self.assertEqual(
            EnrolledMachine.objects.get(serial_number=serial_number).enrollment, enrollment_2)
        self.assertEqual(RecurringJobMachine.objects.filter(serial_number=serial_number).count(), 1)
        events = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], TurboEnrollmentEvent)]
        self.assertEqual(events[-1].payload["action"], "re-enrollment")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_enroll_event(self, post_event):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        serial_number = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True):
            self._enroll(enrollment, serial_number)
        # (re-)enrollment is its own event type, not the heartbeat turbo_request
        events = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], TurboEnrollmentEvent)]
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.event_type, "turbo_enrollment")
        self.assertNotIn("heartbeat", event.tags)
        self.assertEqual(event.metadata.machine_serial_number, serial_number)
        self.assertEqual(event.payload["action"], "enrollment")
        self.assertEqual(event.payload["enrollment"]["pk"], enrollment.pk)
        self.assertEqual(event.payload["configuration"]["pk"], enrollment.configuration.pk)
        self.assertEqual(event.payload["configuration"]["name"], enrollment.configuration.name)
        self.assertEqual(event.get_linked_objects_keys(), {
            "turbo_enrollment": [(enrollment.pk,)],
            "turbo_configuration": [(enrollment.configuration.pk,)],
        })

    # enrollment info endpoint

    def _enrollment_info(self, secret):
        return self.client.get(reverse("turbo_public:enrollment"),
                               HTTP_AUTHORIZATION=f"ZtlEnrollmentSecret {secret}")

    def test_enrollment_info_ok(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        response = self._enrollment_info(enrollment.secret.secret)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"pk": enrollment.pk, "version": enrollment.version})

    def test_enrollment_info_reflects_version_bump(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        enrollment.save()  # BaseEnrollment.save bumps the version on an existing row
        enrollment.refresh_from_db()
        response = self._enrollment_info(enrollment.secret.secret)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["version"], 2)

    def test_enrollment_info_missing_auth(self):
        self.assertEqual(self.client.get(reverse("turbo_public:enrollment")).status_code, 403)

    def test_enrollment_info_unknown_secret(self):
        self.assertEqual(self._enrollment_info(get_random_string(34)).status_code, 403)

    def test_enrollment_info_revoked_secret(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        enrollment.secret.revoked_at = timezone.now()
        enrollment.secret.save()
        self.assertEqual(self._enrollment_info(enrollment.secret.secret).status_code, 403)

    def test_enrollment_info_post_not_allowed(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        response = self.client.post(reverse("turbo_public:enrollment"),
                                    HTTP_AUTHORIZATION=f"ZtlEnrollmentSecret {enrollment.secret.secret}")
        self.assertEqual(response.status_code, 405)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_re_enrollment_event_action(self, post_event):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        serial_number = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True):
            self._enroll(enrollment, serial_number)
        with self.captureOnCommitCallbacks(execute=True):
            self._enroll(enrollment, serial_number)
        events = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], TurboEnrollmentEvent)]
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].payload["action"], "enrollment")
        self.assertEqual(events[1].payload["action"], "re-enrollment")

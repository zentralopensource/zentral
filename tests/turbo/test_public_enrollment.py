import hashlib
import json
import uuid
from unittest.mock import patch
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MachineTag, Tag
from zentral.contrib.turbo.events import TurboRequestEvent
from zentral.contrib.turbo.models import EnrolledMachine, MachineJobStatus
from zentral.core.compliance_checks.models import MachineStatus, Status
from django.utils import timezone
from .utils import TurboPublicTestCase, force_enrollment, force_recurring_job, force_script


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

    def test_enroll_missing_field(self):
        response = self.client.post(
            reverse("turbo_public:enroll"),
            data=json.dumps({"serial_number": get_random_string(12)}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

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
        MachineJobStatus.objects.create(serial_number=serial_number, job=recurring_job.job)
        # re-enrolling into the same enrollment keeps the ledger
        with self.captureOnCommitCallbacks(execute=True):
            self._enroll(enrollment_a, serial_number)
        self.assertEqual(MachineJobStatus.objects.filter(serial_number=serial_number).count(), 1)
        # enrolling into a different configuration drops it
        enrollment_b = force_enrollment(meta_business_unit=self.mbu)
        with self.captureOnCommitCallbacks(execute=True):
            self._enroll(enrollment_b, serial_number)
        self.assertEqual(MachineJobStatus.objects.filter(serial_number=serial_number).count(), 0)

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

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_enroll_event(self, post_event):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        serial_number = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True):
            self._enroll(enrollment, serial_number)
        events = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], TurboRequestEvent)]
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.metadata.machine_serial_number, serial_number)
        self.assertEqual(event.payload["request_type"], "enrollment")
        self.assertEqual(event.payload["action"], "enrollment")
        self.assertEqual(event.payload["enrollment"]["pk"], enrollment.pk)
        self.assertEqual(event.payload["configuration"]["pk"], enrollment.configuration.pk)
        self.assertEqual(event.payload["configuration"]["name"], enrollment.configuration.name)
        self.assertEqual(event.get_linked_objects_keys(), {
            "turbo_enrollment": [(enrollment.pk,)],
            "turbo_configuration": [(enrollment.configuration.pk,)],
        })

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_re_enrollment_event_action(self, post_event):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        serial_number = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True):
            self._enroll(enrollment, serial_number)
        with self.captureOnCommitCallbacks(execute=True):
            self._enroll(enrollment, serial_number)
        events = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], TurboRequestEvent)]
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].payload["action"], "enrollment")
        self.assertEqual(events[1].payload["action"], "re-enrollment")

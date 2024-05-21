import os.path
import plistlib
from unittest.mock import Mock, patch
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from realms.models import RealmAuthenticationSession
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.crypto import verify_signed_payload
from zentral.contrib.mdm.events import OTAEnrollmentRequestEvent
from zentral.contrib.mdm.public_views.ota import ota_enroll_callback
from .utils import force_ota_enrollment, force_ota_enrollment_session, force_realm, force_realm_user


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
@patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
class MDMOTAEnrollmentPublicViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()

    def get_phase_2_payload(self):
        with open(os.path.join(os.path.join(os.path.dirname(__file__), "testdata/ota_playload_phase_2")), "rb") as f:
            return f.read()

    def assertAbort(self, post_event, reason, **kwargs):
        last_event = post_event.call_args.args[0]
        self.assertIsInstance(last_event, OTAEnrollmentRequestEvent)
        self.assertEqual(last_event.payload["status"], "failure")
        self.assertEqual(last_event.payload["reason"], reason)
        for k, v in kwargs.items():
            if k == "serial_number":
                self.assertEqual(last_event.metadata.machine_serial_number, v)
            else:
                self.assertEqual(last_event.payload.get(k), v)

    def assertSuccess(self, post_event, **kwargs):
        last_event = post_event.call_args.args[0]
        self.assertIsInstance(last_event, OTAEnrollmentRequestEvent)
        self.assertEqual(last_event.payload["status"], "success")
        for k, v in kwargs.items():
            self.assertEqual(last_event.payload.get(k), v)

    # enroll

    def test_ota_enrollment_enroll_invalid_secret(self, post_event):
        enrollment = force_ota_enrollment(self.mbu, realm=force_realm())
        enrollment.revoke()
        response = self.client.get(reverse("mdm_public:ota_enrollment_enroll", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 400)

    def test_ota_enrollment_enroll_redirect(self, post_event):
        realm, realm_user = force_realm_user()
        # first request redirects to realm auth
        enrollment = force_ota_enrollment(self.mbu, realm=realm)
        response = self.client.get(reverse("mdm_public:ota_enrollment_enroll", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 302)
        # fake the realm auth
        ras = RealmAuthenticationSession.objects.filter(realm=realm).first()
        self.assertRedirects(response, f"/public/realms/{realm.pk}/ldap/{ras.pk}/login/")
        ras.user = realm_user
        request = Mock()
        request.session = self.client.session
        url = ota_enroll_callback(request, ras, enrollment.pk)
        request.session.save()
        # second request returns the profile service payload
        self.assertEqual(url, reverse("mdm_public:ota_enrollment_enroll", args=(enrollment.pk,)))
        response = self.client.get(reverse("mdm_public:ota_enrollment_enroll", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/x-apple-aspen-config")
        _, profile_data = verify_signed_payload(response.content)
        profile = plistlib.loads(profile_data)
        self.assertEqual(profile["PayloadContent"]["URL"], "https://zentral/public/mdm/ota_session_enroll/")
        self.assertEqual(profile["PayloadOrganization"], enrollment.display_name)

    # ota_enroll

    def test_ota_enroll_no_realm_phase_2_bad_secret(self, post_event):
        force_ota_enrollment(self.mbu)
        response = self.client.post(reverse("mdm_public:ota_enroll"),
                                    data=self.get_phase_2_payload(),
                                    content_type="application/octet-stream")
        self.assertEqual(response.status_code, 400)
        self.assertAbort(post_event, "secret verification failed: 'unknown secret'", phase=2)

    def test_ota_enroll_no_realm_phase_2_blocked(self, post_event):
        session, device_udid, serial_number = force_ota_enrollment_session(self.mbu, completed=True)
        enrollment = session.ota_enrollment
        enrollment.enrollment_secret.secret = "8gLEIttrT7qbLOZs3XzL5XPgNXCliGwRLtn2Lfe4GBsa7g6MGm2sJjicKrLFal4D"
        enrollment.enrollment_secret.save()
        session.enrolled_device.serial_number = "ZDL2M9PTJ3"
        session.enrolled_device.save()
        session.enrolled_device.block()
        response = self.client.post(reverse("mdm_public:ota_enroll"),
                                    data=self.get_phase_2_payload(),
                                    content_type="application/octet-stream")
        self.assertEqual(response.status_code, 400)
        self.assertAbort(post_event, "Device blocked", phase=2)

    def test_ota_enroll_no_realm_phase_2(self, post_event):
        enrollment = force_ota_enrollment(self.mbu)
        enrollment.enrollment_secret.secret = "8gLEIttrT7qbLOZs3XzL5XPgNXCliGwRLtn2Lfe4GBsa7g6MGm2sJjicKrLFal4D"
        enrollment.enrollment_secret.save()
        response = self.client.post(reverse("mdm_public:ota_enroll"),
                                    data=self.get_phase_2_payload(),
                                    content_type="application/octet-stream")
        self.assertEqual(response.status_code, 200)
        _, data = verify_signed_payload(response.content)
        data = plistlib.loads(data)
        self.assertEqual(data["PayloadIdentifier"], "zentral.scep")
        self.assertEqual(len(data["PayloadContent"]), 1)
        self.assertEqual(data["PayloadContent"][0]["PayloadType"], "com.apple.security.scep")
        self.assertSuccess(post_event, phase=2)

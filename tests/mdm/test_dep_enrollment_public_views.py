import base64
import plistlib
from unittest.mock import Mock, patch
import uuid
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.crypto import verify_signed_payload
from zentral.contrib.mdm.events import DEPEnrollmentRequestEvent
from zentral.contrib.mdm.public_views.dep import dep_web_enroll_callback
from .utils import force_dep_enrollment, force_dep_enrollment_session, force_realm_user


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
@patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
@patch("zentral.contrib.mdm.public_views.dep.verify_iphone_ca_signed_payload")
class MDMOTAEnrollmentPublicViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()

    def assertAbort(self, post_event, reason, **kwargs):
        last_event = post_event.call_args.args[0]
        self.assertIsInstance(last_event, DEPEnrollmentRequestEvent)
        self.assertEqual(last_event.payload["status"], "failure")
        self.assertEqual(last_event.payload["reason"], reason)
        for k, v in kwargs.items():
            if k == "serial_number":
                self.assertEqual(last_event.metadata.machine_serial_number, v)
            else:
                self.assertEqual(last_event.payload.get(k), v)

    def assertSuccess(self, post_event, **kwargs):
        last_event = post_event.call_args.args[0]
        self.assertIsInstance(last_event, DEPEnrollmentRequestEvent)
        self.assertEqual(last_event.payload["status"], "success")
        for k, v in kwargs.items():
            self.assertEqual(last_event.payload.get(k), v)

    # dep_enroll

    def test_dep_enroll_invalid_secret(self, vicsp, post_event):
        vicsp.side_effect = lambda d: d
        enrollment = force_dep_enrollment(self.mbu)
        response = self.client.post(reverse("mdm_public:dep_enroll", args=(enrollment.enrollment_secret.secret[:-1],)),
                                    data=plistlib.dumps({"SERIAL": get_random_string(10),
                                                         "UDID": str(uuid.uuid4()).upper()}),
                                    content_type="application/octet-stream")
        self.assertEqual(response.status_code, 400)
        self.assertAbort(post_event, "secret verification failed: 'unknown secret'")

    def test_dep_enroll_realm(self, vicsp, post_event):
        vicsp.side_effect = lambda d: d
        session, _, _ = force_dep_enrollment_session(self.mbu, realm_user=True)
        enrollment = session.dep_enrollment
        response = self.client.post(reverse("mdm_public:dep_enroll", args=(enrollment.enrollment_secret.secret,)),
                                    data=plistlib.dumps({"SERIAL": get_random_string(10),
                                                         "UDID": str(uuid.uuid4()).upper()}),
                                    content_type="application/octet-stream")
        self.assertEqual(response.status_code, 400)
        self.assertAbort(post_event, "this DEP enrollment requires an authenticated realm user")

    def test_dep_enroll_blocked(self, vicsp, post_event):
        vicsp.side_effect = lambda d: d
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        session.enrolled_device.block()
        enrollment = session.dep_enrollment
        response = self.client.post(reverse("mdm_public:dep_enroll", args=(enrollment.enrollment_secret.secret,)),
                                    data=plistlib.dumps({"SERIAL": session.enrolled_device.serial_number,
                                                         "UDID": session.enrolled_device.udid}),
                                    content_type="application/octet-stream")
        self.assertEqual(response.status_code, 400)
        self.assertAbort(post_event, "Device blocked")

    def test_dep_enroll(self, vicsp, post_event):
        vicsp.side_effect = lambda d: d
        enrollment = force_dep_enrollment(self.mbu)
        response = self.client.post(reverse("mdm_public:dep_enroll", args=(enrollment.enrollment_secret.secret,)),
                                    data=plistlib.dumps({"SERIAL": get_random_string(10),
                                                         "UDID": str(uuid.uuid4()).upper()}),
                                    content_type="application/octet-stream")
        self.assertEqual(response.status_code, 200)
        self.assertSuccess(post_event)
        _, data = verify_signed_payload(response.content)
        payload = plistlib.loads(data)
        self.assertEqual(payload["PayloadIdentifier"], "zentral.mdm")

    # dep_web_enroll

    def test_dep_web_enroll_missing_header(self, vicsp, post_event):
        vicsp.side_effect = lambda d: d
        session, _, _ = force_dep_enrollment_session(self.mbu, realm_user=True)
        enrollment = session.dep_enrollment
        response = self.client.get(reverse("mdm_public:dep_web_enroll", args=(enrollment.enrollment_secret.secret,)))
        self.assertEqual(response.status_code, 400)
        self.assertAbort(post_event, "Missing x-apple-aspen-deviceinfo header")

    def test_dep_web_enroll_no_realm(self, vicsp, post_event):
        vicsp.side_effect = lambda d: d
        enrollment = force_dep_enrollment(self.mbu)
        response = self.client.get(reverse("mdm_public:dep_web_enroll", args=(enrollment.enrollment_secret.secret,)),
                                   HTTP_X_APPLE_ASPEN_DEVICEINFO=base64.b64encode(
                                       plistlib.dumps({
                                           "SERIAL": get_random_string(10),
                                           "UDID": str(uuid.uuid4()).upper()
                                       })
                                    ).decode("ascii"))
        self.assertEqual(response.status_code, 400)
        self.assertAbort(post_event, "this DEP enrollment has no realm")

    def test_dep_web_enroll_blocked(self, vicsp, post_event):
        vicsp.side_effect = lambda d: d
        session, _, _ = force_dep_enrollment_session(self.mbu, realm_user=True, completed=True)
        enrollment = session.dep_enrollment
        enrolled_device = session.enrolled_device
        enrolled_device.block()
        response = self.client.get(reverse("mdm_public:dep_web_enroll", args=(enrollment.enrollment_secret.secret,)),
                                   HTTP_X_APPLE_ASPEN_DEVICEINFO=base64.b64encode(
                                       plistlib.dumps({
                                           "SERIAL": enrolled_device.serial_number,
                                           "UDID": enrolled_device.udid,
                                       })
                                    ).decode("ascii"))
        self.assertEqual(response.status_code, 400)
        self.assertAbort(post_event, "Device blocked")

    def test_dep_web_enroll(self, vicsp, post_event):
        vicsp.side_effect = lambda d: d
        session, _, _ = force_dep_enrollment_session(self.mbu, realm_user=True)
        enrollment = session.dep_enrollment
        serial_number = get_random_string(10)
        udid = str(uuid.uuid4()).upper()
        payload = {"SERIAL": serial_number, "UDID": udid}
        # first  request redirects to realm auth
        response = self.client.get(reverse("mdm_public:dep_web_enroll", args=(enrollment.enrollment_secret.secret,)),
                                   HTTP_X_APPLE_ASPEN_DEVICEINFO=base64.b64encode(
                                       plistlib.dumps(payload)
                                    ).decode("ascii"))
        self.assertEqual(response.status_code, 302)
        realm = enrollment.realm
        ras = realm.realmauthenticationsession_set.first()
        self.assertEqual(response.url, f"/public/realms/{realm.pk}/ldap/{ras.pk}/login/")
        self.assertEqual(ras.callback, "zentral.contrib.mdm.public_views.dep.dep_web_enroll_callback")
        self.assertEqual(ras.callback_kwargs, {"dep_enrollment_pk": enrollment.pk,
                                               "serial_number": serial_number,
                                               "udid": udid,
                                               "payload": payload})
        # fake the realm auth
        _, ras.user = force_realm_user(realm)
        request = Mock()
        request.session = self.client.session
        url = dep_web_enroll_callback(request, ras, enrollment.pk, serial_number, udid, payload)
        request.session.save()
        # second request returns the MDM profile
        dep_enrollment_session = enrollment.depenrollmentsession_set.filter(realm_user=ras.user).first()
        self.assertEqual(url, reverse("mdm_public:dep_enrollment_session",
                                      args=(dep_enrollment_session.enrollment_secret.secret,)))
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/x-apple-aspen-config")
        _, profile_data = verify_signed_payload(response.content)
        profile = plistlib.loads(profile_data)
        self.assertEqual(profile["PayloadIdentifier"], "zentral.mdm")

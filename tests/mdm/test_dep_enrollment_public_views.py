import base64
import datetime
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
from .utils import force_dep_enrollment, force_dep_enrollment_session, force_realm_user, force_software_update


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
@patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
@patch("zentral.contrib.mdm.public_views.dep.verify_iphone_ca_signed_payload")
class MDMDEPEnrollmentPublicViewsTestCase(TestCase):
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
                                    data=plistlib.dumps({"PRODUCT": "Macmini9,1",
                                                         "SERIAL": get_random_string(10),
                                                         "UDID": str(uuid.uuid4()).upper()}),
                                    content_type="application/octet-stream")
        self.assertEqual(response.status_code, 400)
        self.assertAbort(post_event, "secret verification failed: 'unknown secret'")

    def test_dep_enroll_realm(self, vicsp, post_event):
        vicsp.side_effect = lambda d: d
        session, _, _ = force_dep_enrollment_session(self.mbu, realm_user=True)
        enrollment = session.dep_enrollment
        response = self.client.post(reverse("mdm_public:dep_enroll", args=(enrollment.enrollment_secret.secret,)),
                                    data=plistlib.dumps({"PRODUCT": "Macmini9,1",
                                                         "SERIAL": get_random_string(10),
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
                                    data=plistlib.dumps({"PRODUCT": "Macmini9,1",
                                                         "SERIAL": session.enrolled_device.serial_number,
                                                         "UDID": session.enrolled_device.udid}),
                                    content_type="application/octet-stream")
        self.assertEqual(response.status_code, 400)
        self.assertAbort(post_event, "Device blocked")

    def test_dep_enroll_ios_update_required(self, vicsp, post_event):
        vicsp.side_effect = lambda d: d
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        enrollment = session.dep_enrollment
        enrollment.ios_min_version = "17.1 (b)"
        enrollment.save()
        response = self.client.post(reverse("mdm_public:dep_enroll", args=(enrollment.enrollment_secret.secret,)),
                                    data=plistlib.dumps({"PRODUCT": "iPhone14,5",
                                                         "SERIAL": session.enrolled_device.serial_number,
                                                         "UDID": session.enrolled_device.udid,
                                                         "MDM_CAN_REQUEST_SOFTWARE_UPDATE": True,
                                                         "OS_VERSION": "17.0 (a)"}),
                                    content_type="application/octet-stream")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json(),
            {'code': 'com.apple.softwareupdate.required', 'details': {'OSVersion': '17.1 (b)'}}
        )
        last_event = post_event.call_args.args[0]
        self.assertIsInstance(last_event, DEPEnrollmentRequestEvent)
        self.assertEqual(last_event.payload["status"], "warning")
        self.assertEqual(last_event.payload["reason"], "OS update to version 17.1 (b) required")

    def test_dep_enroll_min_macos_update_required(self, vicsp, post_event):
        vicsp.side_effect = lambda d: d
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        enrollment = session.dep_enrollment
        enrollment.macos_min_version = "14.1"
        enrollment.save()
        response = self.client.post(reverse("mdm_public:dep_enroll", args=(enrollment.enrollment_secret.secret,)),
                                    data=plistlib.dumps({"PRODUCT": "Macmini9,1",
                                                         "SERIAL": session.enrolled_device.serial_number,
                                                         "UDID": session.enrolled_device.udid,
                                                         "MDM_CAN_REQUEST_SOFTWARE_UPDATE": True,
                                                         "OS_VERSION": "14.0 (a)"}),
                                    content_type="application/octet-stream")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json(),
            {'code': 'com.apple.softwareupdate.required', 'details': {'OSVersion': '14.1'}}
        )
        last_event = post_event.call_args.args[0]
        self.assertIsInstance(last_event, DEPEnrollmentRequestEvent)
        self.assertEqual(last_event.payload["status"], "warning")
        self.assertEqual(last_event.payload["reason"], "OS update to version 14.1 required")

    def test_dep_enroll_max_macos_update_required(self, vicsp, post_event):
        vicsp.side_effect = lambda d: d
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        force_software_update(
            device_id="J413AP",
            version="14.3.0",
            build="23D56",
            posting_date=datetime.date(2024, 1, 22),
            expiration_date=datetime.date(3000, 1, 2)
        )
        enrollment = session.dep_enrollment
        enrollment.macos_min_version = "14.1"
        enrollment.macos_max_version = "15"
        enrollment.save()
        response = self.client.post(reverse("mdm_public:dep_enroll", args=(enrollment.enrollment_secret.secret,)),
                                    data=plistlib.dumps({"PRODUCT": "Macmini9,1",
                                                         "SERIAL": session.enrolled_device.serial_number,
                                                         "UDID": session.enrolled_device.udid,
                                                         "MDM_CAN_REQUEST_SOFTWARE_UPDATE": True,
                                                         "OS_VERSION": "14.0",
                                                         "VERSION": "23A344",
                                                         "SOFTWARE_UPDATE_DEVICE_ID": "J413AP"}),
                                    content_type="application/octet-stream")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json(),
            {'code': 'com.apple.softwareupdate.required', 'details': {'OSVersion': '14.3',
                                                                      'BuildVersion': '23D56'}}
        )
        last_event = post_event.call_args.args[0]
        self.assertIsInstance(last_event, DEPEnrollmentRequestEvent)
        self.assertEqual(last_event.payload["status"], "warning")
        self.assertEqual(last_event.payload["reason"], "OS update to version 14.3 required")

    def test_dep_enroll_max_macos_no_update_required(self, vicsp, post_event):
        vicsp.side_effect = lambda d: d
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        force_software_update(
            device_id="J413AP",
            version="14.4.0",
            build="23E214",
            posting_date=datetime.date(2024, 3, 7),
            expiration_date=datetime.date(3000, 1, 2)
        )
        enrollment = session.dep_enrollment
        enrollment.macos_min_version = "14.3.1"
        enrollment.macos_max_version = "15"
        enrollment.save()
        response = self.client.post(reverse("mdm_public:dep_enroll", args=(enrollment.enrollment_secret.secret,)),
                                    data=plistlib.dumps({"PRODUCT": "Macmini9,1",
                                                         "SERIAL": session.enrolled_device.serial_number,
                                                         "UDID": session.enrolled_device.udid,
                                                         "MDM_CAN_REQUEST_SOFTWARE_UPDATE": True,
                                                         "OS_VERSION": "14.4",
                                                         "VERSION": "23A214",
                                                         "SOFTWARE_UPDATE_DEVICE_ID": "J413AP"}),
                                    content_type="application/octet-stream")
        self.assertEqual(response.status_code, 200)
        self.assertSuccess(post_event)
        _, data = verify_signed_payload(response.content)
        payload = plistlib.loads(data)
        self.assertEqual(payload["PayloadIdentifier"], "zentral.mdm")

    def test_dep_enroll_max_ios_update_required_min_fallback(self, vicsp, post_event):
        vicsp.side_effect = lambda d: d
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        enrollment = session.dep_enrollment
        enrollment.ios_min_version = "17.3"
        enrollment.ios_max_version = "18"
        enrollment.save()
        force_software_update(
            device_id="iPad11,7",  # match
            version="17.4.0",
            build="23E52",
            posting_date=datetime.date(2500, 1, 2),  # Not available
            expiration_date=datetime.date(3000, 1, 2)
        )
        response = self.client.post(reverse("mdm_public:dep_enroll", args=(enrollment.enrollment_secret.secret,)),
                                    data=plistlib.dumps({"PRODUCT": "iPad11,7",
                                                         "SERIAL": session.enrolled_device.serial_number,
                                                         "UDID": session.enrolled_device.udid,
                                                         "MDM_CAN_REQUEST_SOFTWARE_UPDATE": True,
                                                         "OS_VERSION": "17.2.1",
                                                         "VERSION": "21C66",
                                                         "SOFTWARE_UPDATE_DEVICE_ID": "iPad11,7"}),
                                    content_type="application/octet-stream")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json(),
            {'code': 'com.apple.softwareupdate.required', 'details': {'OSVersion': '17.3'}},
        )
        last_event = post_event.call_args.args[0]
        self.assertIsInstance(last_event, DEPEnrollmentRequestEvent)
        self.assertEqual(last_event.payload["status"], "warning")
        self.assertEqual(last_event.payload["reason"], "OS update to version 17.3 required")

    def test_dep_enroll_no_macos_min_version(self, vicsp, post_event):
        vicsp.side_effect = lambda d: d
        enrollment = force_dep_enrollment(self.mbu)
        response = self.client.post(reverse("mdm_public:dep_enroll", args=(enrollment.enrollment_secret.secret,)),
                                    data=plistlib.dumps({"PRODUCT": "Macmini9,1",
                                                         "SERIAL": get_random_string(10),
                                                         "UDID": str(uuid.uuid4()).upper()}),
                                    content_type="application/octet-stream")
        self.assertEqual(response.status_code, 200)
        self.assertSuccess(post_event)
        _, data = verify_signed_payload(response.content)
        payload = plistlib.loads(data)
        self.assertEqual(payload["PayloadIdentifier"], "zentral.mdm")

    def test_dep_enroll_macos_min_version_ok(self, vicsp, post_event):
        vicsp.side_effect = lambda d: d
        enrollment = force_dep_enrollment(self.mbu)
        enrollment.macos_min_version = "14.0"
        enrollment.save()
        response = self.client.post(reverse("mdm_public:dep_enroll", args=(enrollment.enrollment_secret.secret,)),
                                    data=plistlib.dumps({"PRODUCT": "Macmini9,1",
                                                         "SERIAL": get_random_string(10),
                                                         "UDID": str(uuid.uuid4()).upper(),
                                                         "MDM_CAN_REQUEST_SOFTWARE_UPDATE": True,
                                                         "OS_VERSION": "14.1"}),
                                    content_type="application/octet-stream")
        self.assertEqual(response.status_code, 200)
        self.assertSuccess(post_event)
        _, data = verify_signed_payload(response.content)
        payload = plistlib.loads(data)
        self.assertEqual(payload["PayloadIdentifier"], "zentral.mdm")

    def test_dep_enroll_min_os_version_unknown_product(self, vicsp, post_event):
        vicsp.side_effect = lambda d: d
        enrollment = force_dep_enrollment(self.mbu)
        enrollment.macos_min_version = "14.2"
        enrollment.save()
        response = self.client.post(reverse("mdm_public:dep_enroll", args=(enrollment.enrollment_secret.secret,)),
                                    data=plistlib.dumps({"PRODUCT": "Yolo9,1",
                                                         "SERIAL": get_random_string(10),
                                                         "UDID": str(uuid.uuid4()).upper(),
                                                         "MDM_CAN_REQUEST_SOFTWARE_UPDATE": True,
                                                         "OS_VERSION": "14.1"}),
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
                                           "PRODUCT": "Macmini9,1",
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
                                           "PRODUCT": "Macmini9,1",
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
        payload = {"PRODUCT": "Macmini9,1", "SERIAL": serial_number, "UDID": udid}
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

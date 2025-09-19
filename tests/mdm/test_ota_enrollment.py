import plistlib
from unittest.mock import Mock, patch
import uuid
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.crypto import verify_signed_payload
from zentral.contrib.mdm.models import EnrolledDevice, OTAEnrollment, OTAEnrollmentSession, ReEnrollmentSession
from zentral.contrib.mdm.payloads import build_scep_payload
from .utils import complete_enrollment_session, force_ota_enrollment, force_realm_user


class TestOTAEnrollment(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()

    def test_ota_enrollment_cannot_be_deleted(self):
        enrollment = force_ota_enrollment(self.mbu)
        OTAEnrollmentSession.objects.create_from_machine_info(
            enrollment, get_random_string(12), str(uuid.uuid4())
        )
        self.assertFalse(enrollment.can_be_deleted())

    def test_ota_enrollment_delete_value_error(self):
        enrollment = force_ota_enrollment(self.mbu)
        OTAEnrollmentSession.objects.create_from_machine_info(
            enrollment, get_random_string(12), str(uuid.uuid4())
        )
        with self.assertRaises(ValueError) as cm:
            enrollment.delete()
        self.assertEqual(cm.exception.args[0], f"OTAEnrollment {enrollment.pk} cannot be deleted")

    def test_ota_enrollment_delete_ok(self):
        enrollment = force_ota_enrollment(self.mbu)
        enrollment_pk = enrollment.pk
        enrollment.delete()
        self.assertFalse(OTAEnrollment.objects.filter(pk=enrollment_pk).exists())

    def test_create_ota_enrollment_session(self):
        enrollment = force_ota_enrollment(self.mbu)
        session = OTAEnrollmentSession.objects.create_from_machine_info(
            enrollment, get_random_string(12), str(uuid.uuid4())
        )
        self.assertEqual(session.get_enrollment(), enrollment)
        self.assertEqual(session.status, "PHASE_2")
        self.assertEqual(
            session.serialize_for_event(),
            {"enrollment_session": {"pk": session.pk, "type": "ota", "status": "PHASE_2"}}
        )

    def test_ota_enrollment_session_scep_payload(self):
        enrollment = force_ota_enrollment(self.mbu)
        session = OTAEnrollmentSession.objects.create_from_machine_info(
            enrollment, get_random_string(12), str(uuid.uuid4())
        )
        scep_payload = build_scep_payload(session)
        self.assertEqual(scep_payload["PayloadContent"]["Challenge"],
                         enrollment.scep_issuer.get_backend_kwargs()["challenge"])

    def test_ota_enrollment_reenrollment_session_error(self):
        enrollment = force_ota_enrollment(self.mbu)
        session = OTAEnrollmentSession.objects.create_from_machine_info(
            enrollment, get_random_string(12), str(uuid.uuid4())
        )
        with self.assertRaises(ValueError) as cm:
            ReEnrollmentSession.objects.create_from_enrollment_session(session)
        self.assertEqual(cm.exception.args[0], "The enrollment session doesn't have an enrolled device")

    def test_ota_enrollment_reenrollment_session(self):
        enrollment = force_ota_enrollment(self.mbu)
        session = OTAEnrollmentSession.objects.create_from_machine_info(
            enrollment, get_random_string(12), str(uuid.uuid4())
        )
        session.set_phase3_status()
        complete_enrollment_session(session)
        enrolled_device = EnrolledDevice.objects.get(pk=session.enrolled_device.pk)
        self.assertEqual(enrolled_device.current_enrollment_session, session)
        self.assertEqual(enrolled_device.current_enrollment, enrollment)
        reenrollment_session = ReEnrollmentSession.objects.create_from_enrollment_session(session)
        self.assertEqual(reenrollment_session.get_enrollment(), enrollment)
        self.assertIsNone(reenrollment_session.dep_enrollment)
        self.assertEqual(reenrollment_session.ota_enrollment, enrollment)
        self.assertIsNone(reenrollment_session.user_enrollment)
        self.assertEqual(reenrollment_session.status, ReEnrollmentSession.STARTED)
        self.assertEqual(reenrollment_session.first_enrolled_at, session.created_at)
        self.assertEqual(reenrollment_session.device_enrolled_at, session.device_enrolled_at)
        re_s, ota_s = list(session.enrolled_device.iter_enrollment_session_info())
        self.assertEqual(re_s["session_type"], "RE")
        self.assertEqual(re_s["id"], reenrollment_session.pk)
        self.assertEqual(re_s["status"], "STARTED")
        self.assertEqual(re_s["enrollment_type"], "OTA")
        self.assertEqual(re_s["enrollment_id"], enrollment.pk)
        self.assertEqual(ota_s["session_type"], "OTA")
        self.assertEqual(ota_s["id"], session.pk)
        self.assertEqual(ota_s["status"], "COMPLETED")
        self.assertEqual(ota_s["enrollment_type"], "OTA")
        self.assertEqual(ota_s["enrollment_id"], enrollment.pk)
        enrolled_device = EnrolledDevice.objects.get(pk=session.enrolled_device.pk)
        self.assertEqual(enrolled_device.current_enrollment_session, reenrollment_session)
        self.assertEqual(enrolled_device.current_enrollment, enrollment)

    def test_ota_enrollment_reenrollment_reenrollment_session(self):
        enrollment = force_ota_enrollment(self.mbu)
        session = OTAEnrollmentSession.objects.create_from_machine_info(
            enrollment, get_random_string(12), str(uuid.uuid4())
        )
        session.set_phase3_status()
        complete_enrollment_session(session)
        reenrollment_session = ReEnrollmentSession.objects.create_from_enrollment_session(session)
        complete_enrollment_session(reenrollment_session)
        reenrollment_session2 = ReEnrollmentSession.objects.create_from_enrollment_session(reenrollment_session)
        self.assertEqual(reenrollment_session2.get_enrollment(), enrollment)

    @patch("zentral.contrib.mdm.public_views.ota.verify_apple_iphone_device_ca_issuer")
    @patch("zentral.contrib.mdm.public_views.ota.verify_signed_payload")
    def test_ota_enroll_view_phase_2(
        self,
        mocked_verify_signed_payload,
        mocked_verify_apple_iphone_device_ca_issuer,
    ):
        enrollment = force_ota_enrollment(self.mbu)
        session_qs = enrollment.otaenrollmentsession_set.all()
        self.assertEqual(session_qs.count(), 0)
        payload = {
            "SERIAL": get_random_string(12),
            "UDID": str(uuid.uuid4()).upper(),
            "CHALLENGE": enrollment.enrollment_secret.secret,
        }
        certificates = [(Mock(), Mock(), Mock())]
        mocked_verify_signed_payload.return_value = (certificates, plistlib.dumps(payload))
        mocked_verify_apple_iphone_device_ca_issuer.return_value = True
        response = self.client.post(reverse("mdm_public:ota_enroll"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/x-apple-aspen-config")
        _, profile_data = verify_signed_payload(response.content)
        profile = plistlib.loads(profile_data)
        scep_profile = profile["PayloadContent"][0]
        self.assertEqual(scep_profile["PayloadType"], "com.apple.security.scep")
        self.assertTrue(
            scep_profile["PayloadContent"]["Subject"][0][0][1].startswith("OTA")
        )
        self.assertEqual(session_qs.count(), 1)
        session = session_qs.first()
        self.assertEqual(session.status, OTAEnrollmentSession.PHASE_2)

    @patch("zentral.contrib.mdm.public_views.ota.verify_apple_iphone_device_ca_issuer")
    @patch("zentral.contrib.mdm.public_views.ota.verify_signed_payload")
    def test_ota_session_enroll_view_phase_2(
        self,
        mocked_verify_signed_payload,
        mocked_verify_apple_iphone_device_ca_issuer,
    ):
        realm, realm_user = force_realm_user()
        enrollment = force_ota_enrollment(self.mbu, realm=realm)
        session = OTAEnrollmentSession.objects.create_from_realm_user(enrollment, realm_user)
        payload = {
            "SERIAL": get_random_string(12),
            "UDID": str(uuid.uuid4()).upper(),
            "CHALLENGE": session.enrollment_secret.secret,
        }
        certificates = [(Mock(), Mock(), Mock())]
        mocked_verify_signed_payload.return_value = (certificates, plistlib.dumps(payload))
        mocked_verify_apple_iphone_device_ca_issuer.return_value = True
        response = self.client.post(reverse("mdm_public:ota_session_enroll"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/x-apple-aspen-config")
        _, profile_data = verify_signed_payload(response.content)
        profile = plistlib.loads(profile_data)
        scep_profile = profile["PayloadContent"][0]
        self.assertEqual(scep_profile["PayloadType"], "com.apple.security.scep")
        self.assertTrue(
            scep_profile["PayloadContent"]["Subject"][0][0][1].startswith("OTA")
        )
        session_qs = enrollment.otaenrollmentsession_set.all()
        self.assertEqual(session_qs.count(), 1)
        self.assertEqual(session_qs.first(), session)
        session.refresh_from_db()
        self.assertEqual(session.status, OTAEnrollmentSession.PHASE_2)

    @patch("zentral.contrib.mdm.cert_issuer_backends.base_microsoft_ca.requests.get")
    @patch("zentral.contrib.mdm.public_views.ota.verify_zentral_scep_ca_issuer")
    @patch("zentral.contrib.mdm.public_views.ota.verify_apple_iphone_device_ca_issuer")
    @patch("zentral.contrib.mdm.public_views.ota.verify_signed_payload")
    def test_ota_enroll_view_phase_3(
        self,
        mocked_verify_signed_payload,
        mocked_verify_apple_iphone_device_ca_issuer,
        mocked_verify_zentral_scep_ca_issuer,
        requests_get,
    ):
        enrollment = force_ota_enrollment(self.mbu)
        serial_number = get_random_string(12)
        udid = str(uuid.uuid4()).upper()
        session = OTAEnrollmentSession.objects.create_from_machine_info(enrollment, serial_number, udid)
        payload = {
            "SERIAL": serial_number,
            "UDID": udid,
            "CHALLENGE": session.enrollment_secret.secret,
            "PRODUCT": "Mac14,2",
            "OS_VERSION": "15.6.1",
        }
        signing_certificate = Mock()
        serial_number_attr = Mock()
        serial_number_attr.value = serial_number
        common_name_attr = Mock()
        common_name_attr.value = f"OTA${session.enrollment_secret.secret}"
        o_attr = Mock()
        o_attr.value = f"MBU${self.mbu.pk}"
        signing_certificate.subject.get_attributes_for_oid.side_effect = [
            [serial_number_attr],
            [common_name_attr],
            [o_attr],
        ]
        certificates = [(Mock(), Mock(), signing_certificate)]
        mocked_verify_signed_payload.return_value = (certificates, plistlib.dumps(payload))
        mocked_verify_apple_iphone_device_ca_issuer.return_value = False
        mocked_verify_zentral_scep_ca_issuer.return_value = True
        challenge_resp = Mock()
        challenge_resp.content.decode.return_value = "challenge password is: <B> 1000000000000002 </B>"
        requests_get.return_value = challenge_resp
        response = self.client.post(reverse("mdm_public:ota_enroll"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/x-apple-aspen-config")
        _, profile_data = verify_signed_payload(response.content)
        profile = plistlib.loads(profile_data)
        payload_content = profile["PayloadContent"]
        self.assertEqual(len(payload_content), 3)
        self.assertEqual(payload_content[0]["PayloadType"], "com.apple.security.pem")  # cert chain
        self.assertEqual(payload_content[1]["PayloadType"], "com.apple.security.acme")  # ACME
        self.assertEqual(payload_content[2]["PayloadType"], "com.apple.mdm")  # MDM
        session_qs = enrollment.otaenrollmentsession_set.all()
        self.assertEqual(session_qs.count(), 1)
        self.assertEqual(session_qs.first(), session)
        session.refresh_from_db()
        self.assertEqual(session.status, OTAEnrollmentSession.PHASE_3)

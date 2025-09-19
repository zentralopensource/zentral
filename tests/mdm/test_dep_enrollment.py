from unittest.mock import Mock, patch
import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from realms.models import Realm, RealmUser
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.models import DEPEnrollment, DEPEnrollmentSession, EnrolledDevice, ReEnrollmentSession
from zentral.contrib.mdm.payloads import build_acme_payload, build_scep_payload
from .utils import complete_enrollment_session, force_dep_enrollment, force_realm_user


class TestDEPEnrollment(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.realm = Realm.objects.create(
            name=get_random_string(12),
            backend="ldap",
            username_claim="username",
            email_claim="email",
        )
        username = get_random_string(12)
        email = f"{username}@example.com"
        cls.realm_user = RealmUser.objects.create(
            realm=cls.realm,
            claims={"username": username,
                    "email": email},
            username=username,
            email=email,
        )

    def test_dep_enrollment_cannot_be_deleted(self):
        enrollment = force_dep_enrollment(self.mbu)
        DEPEnrollmentSession.objects.create_from_dep_enrollment(
            enrollment, get_random_string(12), str(uuid.uuid4())
        )
        self.assertFalse(enrollment.can_be_deleted())

    def test_dep_enrollment_delete_value_error(self):
        enrollment = force_dep_enrollment(self.mbu)
        DEPEnrollmentSession.objects.create_from_dep_enrollment(
            enrollment, get_random_string(12), str(uuid.uuid4())
        )
        with self.assertRaises(ValueError) as cm:
            enrollment.delete()
        self.assertEqual(cm.exception.args[0], f"DEPEnrollment {enrollment.pk} cannot be deleted")

    def test_dep_enrollment_delete_ok(self):
        enrollment = force_dep_enrollment(self.mbu)
        enrollment_pk = enrollment.pk
        enrollment.delete()
        self.assertFalse(DEPEnrollment.objects.filter(pk=enrollment_pk).exists())

    def test_create_dep_enrollment_session(self):
        enrollment = force_dep_enrollment(self.mbu)
        session = DEPEnrollmentSession.objects.create_from_dep_enrollment(
            enrollment, get_random_string(12), str(uuid.uuid4())
        )
        self.assertEqual(session.get_enrollment(), enrollment)
        self.assertEqual(session.status, "STARTED")
        self.assertEqual(
            session.serialize_for_event(),
            {"enrollment_session": {"pk": session.pk, "type": "dep", "status": "STARTED"}}
        )

    def test_dep_enrollment_session_no_acme_payload(self):
        enrollment = force_dep_enrollment(self.mbu)
        session = DEPEnrollmentSession.objects.create_from_dep_enrollment(
            enrollment, get_random_string(12), str(uuid.uuid4())
        )
        self.assertIsNone(build_acme_payload(session, {"PRODUCT": "Mac14,2", "OS_VERSION": "15.6.1"}))

    @patch("zentral.contrib.mdm.cert_issuer_backends.base_microsoft_ca.requests.get")
    def test_dep_enrollment_session_acme_payload(self, requests_get):
        response = Mock()
        response.content.decode.return_value = "challenge password is: <B> 1000000000000002 </B>"
        requests_get.return_value = response
        enrollment = force_dep_enrollment(self.mbu, acme_issuer=True)
        session = DEPEnrollmentSession.objects.create_from_dep_enrollment(
            enrollment, get_random_string(12), str(uuid.uuid4())
        )
        acme_payload = build_acme_payload(session, {"PRODUCT": "Mac14,2", "OS_VERSION": "15.6.1"})
        self.assertTrue(acme_payload["AllowAllAppsAccess"] is False)
        self.assertTrue(acme_payload["KeyIsExtractable"] is False)
        self.assertTrue(acme_payload["KeyType"], "ECSECPrimeRandom")
        self.assertTrue(acme_payload["KeySize"], 384)
        self.assertTrue(acme_payload["ClientIdentifier"], "1000000000000002")

    def test_dep_enrollment_session_scep_payload(self):
        enrollment = force_dep_enrollment(self.mbu)
        session = DEPEnrollmentSession.objects.create_from_dep_enrollment(
            enrollment, get_random_string(12), str(uuid.uuid4())
        )
        scep_payload = build_scep_payload(session)
        self.assertEqual(scep_payload["PayloadContent"]["Challenge"],
                         enrollment.scep_issuer.get_backend_kwargs()["challenge"])

    def test_dep_enrollment_reenrollment_session_error(self):
        enrollment = force_dep_enrollment(self.mbu)
        session = DEPEnrollmentSession.objects.create_from_dep_enrollment(
            enrollment, get_random_string(12), str(uuid.uuid4())
        )
        with self.assertRaises(ValueError) as cm:
            ReEnrollmentSession.objects.create_from_enrollment_session(session)
        self.assertEqual(cm.exception.args[0], "The enrollment session doesn't have an enrolled device")

    def test_dep_enrollment_reenrollment_session(self):
        enrollment = force_dep_enrollment(self.mbu)
        enrollment.realm, realm_user = force_realm_user()
        enrollment.save()
        session = DEPEnrollmentSession.objects.create_from_dep_enrollment(
            enrollment, get_random_string(12), str(uuid.uuid4())
        )
        session.realm_user = realm_user
        session.save()
        complete_enrollment_session(session)
        enrolled_device = EnrolledDevice.objects.get(pk=session.enrolled_device.pk)
        self.assertEqual(enrolled_device.current_enrollment_session, session)
        self.assertEqual(enrolled_device.current_enrollment, enrollment)
        reenrollment_session = ReEnrollmentSession.objects.create_from_enrollment_session(session)
        self.assertEqual(reenrollment_session.get_enrollment(), enrollment)
        self.assertEqual(reenrollment_session.dep_enrollment, enrollment)
        self.assertIsNone(reenrollment_session.ota_enrollment)
        self.assertIsNone(reenrollment_session.user_enrollment)
        self.assertEqual(reenrollment_session.status, ReEnrollmentSession.STARTED)
        self.assertEqual(reenrollment_session.realm_user, realm_user)
        self.assertEqual(reenrollment_session.first_enrolled_at, session.created_at)
        self.assertEqual(reenrollment_session.device_enrolled_at, session.device_enrolled_at)
        re_s, dep_s = list(session.enrolled_device.iter_enrollment_session_info())
        self.assertEqual(re_s["session_type"], "RE")
        self.assertEqual(re_s["id"], reenrollment_session.pk)
        self.assertEqual(re_s["status"], "STARTED")
        self.assertEqual(re_s["enrollment_type"], "DEP")
        self.assertEqual(re_s["enrollment_id"], enrollment.pk)
        self.assertEqual(dep_s["session_type"], "DEP")
        self.assertEqual(dep_s["id"], session.pk)
        self.assertEqual(dep_s["status"], "COMPLETED")
        self.assertEqual(dep_s["enrollment_type"], "DEP")
        self.assertEqual(dep_s["enrollment_id"], enrollment.pk)
        enrolled_device = EnrolledDevice.objects.get(pk=session.enrolled_device.pk)
        self.assertEqual(enrolled_device.current_enrollment_session, reenrollment_session)
        self.assertEqual(enrolled_device.current_enrollment, enrollment)

    def test_dep_enrollment_reenrollment_reenrollment_session(self):
        enrollment = force_dep_enrollment(self.mbu)
        session = DEPEnrollmentSession.objects.create_from_dep_enrollment(
            enrollment, get_random_string(12), str(uuid.uuid4())
        )
        complete_enrollment_session(session)
        reenrollment_session = ReEnrollmentSession.objects.create_from_enrollment_session(session)
        complete_enrollment_session(reenrollment_session)
        reenrollment_session2 = ReEnrollmentSession.objects.create_from_enrollment_session(reenrollment_session)
        self.assertEqual(reenrollment_session2.get_enrollment(), enrollment)
        self.assertIsNone(reenrollment_session2.realm_user)

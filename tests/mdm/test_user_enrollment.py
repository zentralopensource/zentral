from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.models import ReEnrollmentSession, UserEnrollment, UserEnrollmentSession
from zentral.contrib.mdm.payloads import build_scep_payload
from .utils import complete_enrollment_session, force_realm_user, force_user_enrollment


class TestUserEnrollment(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.realm, cls.realm_user = force_realm_user()

    def test_user_enrollment_cannot_be_deleted(self):
        enrollment = force_user_enrollment(self.mbu, self.realm)
        UserEnrollmentSession.objects.create_from_user_enrollment(enrollment)
        self.assertFalse(enrollment.can_be_deleted())

    def test_user_enrollment_delete_value_error(self):
        enrollment = force_user_enrollment(self.mbu, self.realm)
        UserEnrollmentSession.objects.create_from_user_enrollment(enrollment)
        with self.assertRaises(ValueError) as cm:
            enrollment.delete()
        self.assertEqual(cm.exception.args[0], f"UserEnrollment {enrollment.pk} cannot be deleted")

    def test_user_enrollment_delete_ok(self):
        enrollment = force_user_enrollment(self.mbu, self.realm)
        enrollment_pk = enrollment.pk
        enrollment.delete()
        self.assertFalse(UserEnrollment.objects.filter(pk=enrollment_pk).exists())

    def test_create_user_enrollment_session_no_managed_apple_id(self):
        enrollment = force_user_enrollment(self.mbu, self.realm)
        session = UserEnrollmentSession.objects.create_from_user_enrollment(enrollment)
        self.assertEqual(session.get_enrollment(), enrollment)
        self.assertEqual(session.status, "ACCOUNT_DRIVEN_START")
        self.assertEqual(
            session.serialize_for_event(),
            {"enrollment_session": {"pk": session.pk, "type": "user", "status": "ACCOUNT_DRIVEN_START"}}
        )

    def test_user_enrollment_session_scep_payload(self):
        enrollment = force_user_enrollment(self.mbu, self.realm)
        session = UserEnrollmentSession.objects.create_from_user_enrollment(enrollment)
        session.set_account_driven_authenticated_status(self.realm_user)
        session.set_started_status()
        scep_payload = build_scep_payload(session)
        self.assertEqual(scep_payload["PayloadContent"]["Challenge"],
                         enrollment.scep_config.get_challenge_kwargs()["challenge"])

    def test_user_enrollment_reenrollment_session_error(self):
        enrollment = force_user_enrollment(self.mbu, self.realm)
        session = UserEnrollmentSession.objects.create_from_user_enrollment(enrollment)
        with self.assertRaises(ValueError) as cm:
            ReEnrollmentSession.objects.create_from_enrollment_session(session)
        self.assertEqual(cm.exception.args[0], "The enrollment session doesn't have an enrolled device")

    def test_user_enrollment_reenrollment_session(self):
        enrollment = force_user_enrollment(self.mbu, self.realm)
        session = UserEnrollmentSession.objects.create_from_user_enrollment(enrollment)
        session.set_account_driven_authenticated_status(self.realm_user)
        session.set_started_status()
        complete_enrollment_session(session)
        reenrollment_session = ReEnrollmentSession.objects.create_from_enrollment_session(session)
        self.assertEqual(reenrollment_session.get_enrollment(), enrollment)
        self.assertIsNone(reenrollment_session.dep_enrollment)
        self.assertIsNone(reenrollment_session.ota_enrollment)
        self.assertEqual(reenrollment_session.user_enrollment, enrollment)
        self.assertEqual(reenrollment_session.status, ReEnrollmentSession.STARTED)
        self.assertEqual(reenrollment_session.first_enrolled_at, session.created_at)
        self.assertEqual(reenrollment_session.device_enrolled_at, session.device_enrolled_at)
        re_s, user_s = list(session.enrolled_device.iter_enrollment_session_info())
        self.assertEqual(re_s["session_type"], "RE")
        self.assertEqual(re_s["id"], reenrollment_session.pk)
        self.assertEqual(re_s["status"], "STARTED")
        self.assertEqual(re_s["enrollment_type"], "USER")
        self.assertEqual(re_s["enrollment_id"], enrollment.pk)
        self.assertEqual(user_s["session_type"], "USER")
        self.assertEqual(user_s["id"], session.pk)
        self.assertEqual(user_s["status"], "COMPLETED")
        self.assertEqual(user_s["realm_username"], session.realm_user.username)
        self.assertEqual(user_s["enrollment_type"], "USER")
        self.assertEqual(user_s["enrollment_id"], enrollment.pk)

    def test_user_enrollment_reenrollment_reenrollment_session(self):
        enrollment = force_user_enrollment(self.mbu, self.realm)
        session = UserEnrollmentSession.objects.create_from_user_enrollment(enrollment)
        session.set_account_driven_authenticated_status(self.realm_user)
        session.set_started_status()
        complete_enrollment_session(session)
        reenrollment_session = ReEnrollmentSession.objects.create_from_enrollment_session(session)
        complete_enrollment_session(reenrollment_session)
        reenrollment_session2 = ReEnrollmentSession.objects.create_from_enrollment_session(reenrollment_session)
        self.assertEqual(reenrollment_session2.get_enrollment(), enrollment)

import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.models import OTAEnrollmentSession, ReEnrollmentSession
from zentral.contrib.mdm.payloads import build_scep_payload
from .utils import complete_enrollment_session, force_ota_enrollment


class TestOTAEnrollment(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()

    def test_create_ota_enrollment_session(self):
        enrollment = force_ota_enrollment(self.mbu)
        session = OTAEnrollmentSession.objects.create_from_machine_info(
            enrollment, get_random_string(12), str(uuid.uuid4())
        )
        self.assertEqual(session.get_enrollment(), enrollment)
        self.assertEqual(session.status, "PHASE_2")

    def test_ota_enrollment_session_scep_payload(self):
        enrollment = force_ota_enrollment(self.mbu)
        session = OTAEnrollmentSession.objects.create_from_machine_info(
            enrollment, get_random_string(12), str(uuid.uuid4())
        )
        scep_payload = build_scep_payload(session)
        self.assertEqual(scep_payload["PayloadContent"]["Challenge"],
                         enrollment.scep_config.get_challenge_kwargs()["challenge"])

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
        reenrollment_session = ReEnrollmentSession.objects.create_from_enrollment_session(session)
        self.assertEqual(reenrollment_session.get_enrollment(), enrollment)
        self.assertIsNone(reenrollment_session.dep_enrollment)
        self.assertEqual(reenrollment_session.ota_enrollment, enrollment)
        self.assertIsNone(reenrollment_session.user_enrollment)
        self.assertEqual(reenrollment_session.status, ReEnrollmentSession.STARTED)

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

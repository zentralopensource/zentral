import base64
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.events import EnrollmentSecretVerificationEvent
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.events import MDMSCEPVerificationEvent
from zentral.contrib.mdm.models import ReEnrollmentSession
from zentral.utils.api_views import make_secret
from .utils import force_dep_enrollment_session, force_ota_enrollment_session, force_user_enrollment_session


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
@patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
class SCEPViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()

    # utility methods

    def _generate_csr(self, session=None, serial_number=None, cn=None, org=None):
        if serial_number is None:
            if session:
                serial_number = session.enrollment_secret.serial_numbers[0]
            else:
                serial_number = get_random_string(12)
        privkey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=512
        )  # lgtm[py/weak-crypto-key]
        if session:
            cn = session.get_common_name()
            org = session.get_organization()
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, serial_number),
        ])).sign(privkey, hashes.SHA256())
        return base64.b64encode(csr.public_bytes(serialization.Encoding.DER)).decode("ascii")

    def _post_csr(self, csr_pem):
        kwargs = {"data": {"csr": csr_pem},
                  "content_type": "application/json",
                  "HTTP_ZENTRAL_API_SECRET": make_secret("zentral")}
        return self.client.post(reverse("mdm_public:verify_scep_csr"), **kwargs)

    # tests

    def test_permission_denied(self, post_event):
        response = self.client.post(reverse("mdm_public:verify_scep_csr"))
        self.assertEqual(response.status_code, 403)

    def test_dep_enrollment_session_ok(self, post_event):
        dep_enrollment_session, _, serial_number = force_dep_enrollment_session(self.mbu)
        self.assertEqual(dep_enrollment_session.status, "STARTED")
        self.assertIsNone(dep_enrollment_session.scep_request)
        csr_pem = self._generate_csr(dep_enrollment_session)
        response = self._post_csr(csr_pem)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": 0})
        dep_enrollment_session.refresh_from_db()
        self.assertEqual(dep_enrollment_session.status, "SCEP_VERIFIED")
        self.assertEqual(dep_enrollment_session.scep_request.serial_number, serial_number)
        self.assertEqual(len(post_event.call_args_list), 2)
        ev_event, scep_event = post_event.call_args_list[0].args[0], post_event.call_args_list[1].args[0]
        self.assertIsInstance(ev_event, EnrollmentSecretVerificationEvent)
        self.assertIsInstance(scep_event, MDMSCEPVerificationEvent)
        self.assertEqual(scep_event.metadata.machine_serial_number, serial_number)
        self.assertEqual(scep_event.payload["scep_status"], "success")
        self.assertEqual(scep_event.payload["enrollment_session"]["pk"], dep_enrollment_session.pk)
        self.assertEqual(scep_event.payload["enrollment_session"]["type"], "dep")

    def test_ota_enrollment_session_phase2_ok(self, post_event):
        ota_enrollment_session, _, serial_number = force_ota_enrollment_session(self.mbu)
        self.assertEqual(ota_enrollment_session.status, "PHASE_2")
        self.assertIsNone(ota_enrollment_session.phase2_scep_request)
        csr_pem = self._generate_csr(ota_enrollment_session)
        response = self._post_csr(csr_pem)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": 0})
        ota_enrollment_session.refresh_from_db()
        self.assertEqual(ota_enrollment_session.status, "PHASE_2_SCEP_VERIFIED")
        self.assertEqual(ota_enrollment_session.phase2_scep_request.serial_number, serial_number)
        self.assertEqual(len(post_event.call_args_list), 2)
        ev_event, scep_event = post_event.call_args_list[0].args[0], post_event.call_args_list[1].args[0]
        self.assertIsInstance(ev_event, EnrollmentSecretVerificationEvent)
        self.assertIsInstance(scep_event, MDMSCEPVerificationEvent)
        self.assertEqual(scep_event.metadata.machine_serial_number, serial_number)
        self.assertEqual(scep_event.payload["scep_status"], "success")
        self.assertEqual(scep_event.payload["enrollment_session"]["pk"], ota_enrollment_session.pk)
        self.assertEqual(scep_event.payload["enrollment_session"]["type"], "ota")

    def test_ota_enrollment_session_phase3_ok(self, post_event):
        ota_enrollment_session, _, serial_number = force_ota_enrollment_session(self.mbu, phase3=True)
        self.assertEqual(ota_enrollment_session.status, "PHASE_3")
        self.assertIsNone(ota_enrollment_session.phase3_scep_request)
        csr_pem = self._generate_csr(ota_enrollment_session)
        response = self._post_csr(csr_pem)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": 0})
        ota_enrollment_session.refresh_from_db()
        self.assertEqual(ota_enrollment_session.status, "PHASE_3_SCEP_VERIFIED")
        self.assertEqual(ota_enrollment_session.phase3_scep_request.serial_number, serial_number)
        self.assertEqual(len(post_event.call_args_list), 2)
        ev_event, scep_event = post_event.call_args_list[0].args[0], post_event.call_args_list[1].args[0]
        self.assertIsInstance(ev_event, EnrollmentSecretVerificationEvent)
        self.assertIsInstance(scep_event, MDMSCEPVerificationEvent)
        self.assertEqual(scep_event.metadata.machine_serial_number, serial_number)
        self.assertEqual(scep_event.payload["scep_status"], "success")
        self.assertEqual(scep_event.payload["enrollment_session"]["pk"], ota_enrollment_session.pk)
        self.assertEqual(scep_event.payload["enrollment_session"]["type"], "ota")

    def test_reenrollment_session_ok(self, post_event):
        dep_enrollment_session, _, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        reenrollment_session = ReEnrollmentSession.objects.create_from_enrollment_session(dep_enrollment_session)
        self.assertEqual(reenrollment_session.status, "STARTED")
        self.assertIsNone(reenrollment_session.scep_request)
        csr_pem = self._generate_csr(reenrollment_session)
        response = self._post_csr(csr_pem)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": 0})
        reenrollment_session.refresh_from_db()
        self.assertEqual(reenrollment_session.status, "SCEP_VERIFIED")
        self.assertEqual(reenrollment_session.scep_request.serial_number, serial_number)
        self.assertEqual(len(post_event.call_args_list), 2)
        ev_event, scep_event = post_event.call_args_list[0].args[0], post_event.call_args_list[1].args[0]
        self.assertIsInstance(ev_event, EnrollmentSecretVerificationEvent)
        self.assertIsInstance(scep_event, MDMSCEPVerificationEvent)
        self.assertEqual(scep_event.metadata.machine_serial_number, serial_number)
        self.assertEqual(scep_event.payload["scep_status"], "success")
        self.assertEqual(scep_event.payload["enrollment_session"]["pk"], reenrollment_session.pk)
        self.assertEqual(scep_event.payload["enrollment_session"]["type"], "re")

    def test_user_enrollment_session_ok(self, post_event):
        user_enrollment_session, _, _ = force_user_enrollment_session(self.mbu)
        self.assertEqual(user_enrollment_session.status, "STARTED")
        self.assertIsNone(user_enrollment_session.scep_request)
        serial_number = get_random_string(12)
        csr_pem = self._generate_csr(user_enrollment_session, serial_number)
        response = self._post_csr(csr_pem)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": 0})
        user_enrollment_session.refresh_from_db()
        self.assertEqual(user_enrollment_session.status, "SCEP_VERIFIED")
        self.assertEqual(user_enrollment_session.scep_request.serial_number, serial_number)
        self.assertEqual(len(post_event.call_args_list), 2)
        ev_event, scep_event = post_event.call_args_list[0].args[0], post_event.call_args_list[1].args[0]
        self.assertIsInstance(ev_event, EnrollmentSecretVerificationEvent)
        self.assertIsInstance(scep_event, MDMSCEPVerificationEvent)
        self.assertEqual(scep_event.metadata.machine_serial_number, serial_number)
        self.assertEqual(scep_event.payload["scep_status"], "success")
        self.assertEqual(scep_event.payload["enrollment_session"]["pk"], user_enrollment_session.pk)
        self.assertEqual(scep_event.payload["enrollment_session"]["type"], "user")

    def test_unknown_org_name_format(self, post_event):
        csr_pem = self._generate_csr(cn="YOLO", org="FOMO")
        response = self._post_csr(csr_pem)
        self.assertEqual(response.status_code, 400)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MDMSCEPVerificationEvent)
        self.assertEqual(event.payload["scep_status"], "failure")
        self.assertEqual(event.payload["reason"], "Unknown organization name format")

    def test_unknown_common_name_format(self, post_event):
        csr_pem = self._generate_csr(cn="YOLO", org=f"MBU${self.mbu.pk}")
        response = self._post_csr(csr_pem)
        self.assertEqual(response.status_code, 400)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MDMSCEPVerificationEvent)
        self.assertEqual(event.payload["scep_status"], "failure")
        self.assertEqual(event.payload["reason"], "Unknown common name format")

    def test_unknown_cn_prefix(self, post_event):
        csr_pem = self._generate_csr(cn="YOLO$FOMO", org=f"MBU${self.mbu.pk}")
        response = self._post_csr(csr_pem)
        self.assertEqual(response.status_code, 400)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MDMSCEPVerificationEvent)
        self.assertEqual(event.payload["scep_status"], "failure")
        self.assertEqual(event.payload["reason"], "Unknown CN prefix YOLO")

    def test_bad_csr(self, post_event):
        response = self._post_csr("yolo")
        self.assertEqual(response.status_code, 400)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MDMSCEPVerificationEvent)
        self.assertEqual(event.payload["scep_status"], "failure")
        self.assertEqual(event.payload["reason"], "Could not load CSR")

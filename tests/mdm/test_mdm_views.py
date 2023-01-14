from datetime import datetime, timedelta
import json
import plistlib
from unittest.mock import patch
from urllib.parse import quote
import uuid
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.crypto import verify_signed_payload
from zentral.contrib.mdm.declarations import (get_blueprint_tokens_response,
                                              update_blueprint_activation,
                                              update_blueprint_declaration_items)
from zentral.contrib.mdm.events import MDMRequestEvent
from zentral.contrib.mdm.models import (Blueprint, DEPEnrollmentSession, DeviceCommand, EnrolledDevice,
                                        OTAEnrollmentSession, UserEnrollmentSession, ReEnrollmentSession)
from .utils import (force_dep_enrollment_session,
                    force_enrolled_user,
                    force_ota_enrollment_session,
                    force_user_enrollment_session)


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
@patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
class MDMViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()

    # utility methods

    def _put(self, url, payload, session=None, certificate=True, serial_number=None):
        kwargs = {}
        if payload:
            kwargs["data"] = plistlib.dumps(payload)
        if session:
            secret = session.enrollment_secret.secret
            if serial_number is None:
                serial_number = session.enrollment_secret.serial_numbers[0]
            if isinstance(session, DEPEnrollmentSession):
                enrollment_type = "DEP"
            elif isinstance(session, OTAEnrollmentSession):
                enrollment_type = "OTA"
            elif isinstance(session, ReEnrollmentSession):
                enrollment_type = "RE"
            else:
                enrollment_type = "USER"
            cn = f"MDM${enrollment_type}${secret}"
            kwargs["HTTP_X_SSL_CLIENT_S_DN"] = f"serialNumber={serial_number},CN={cn},O=MBU${self.mbu.pk}"
            if certificate:
                privkey = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=512,  # faster
                )
                builder = x509.CertificateBuilder()
                builder = builder.subject_name(x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, cn),
                ]))
                builder = builder.issuer_name(x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, cn),
                ]))
                builder = builder.not_valid_before(datetime.today() - timedelta(days=1))
                builder = builder.not_valid_after(datetime(2034, 5, 6))
                builder = builder.serial_number(x509.random_serial_number())
                builder = builder.public_key(privkey.public_key())
                cert = builder.sign(
                    private_key=privkey, algorithm=hashes.SHA256(),
                )
                cert_pem = cert.public_bytes(
                    encoding=serialization.Encoding.PEM
                )
                kwargs["HTTP_X_SSL_CLIENT_CERT"] = quote(cert_pem)
        return self.client.put(url, **kwargs)

    def _assertAbort(self, post_event, reason, **kwargs):
        last_event = post_event.call_args.args[0]
        self.assertIsInstance(last_event, MDMRequestEvent)
        self.assertEqual(last_event.payload["status"], "failure")
        self.assertEqual(last_event.payload["reason"], reason)
        for k, v in kwargs.items():
            if k == "serial_number":
                self.assertEqual(last_event.metadata.machine_serial_number, v)
            else:
                self.assertEqual(last_event.payload.get(k), v)

    def _assertSuccess(self, post_event, **kwargs):
        last_event = post_event.call_args.args[0]
        self.assertIsInstance(last_event, MDMRequestEvent)
        self.assertEqual(last_event.payload["status"], "success")
        for k, v in kwargs.items():
            self.assertEqual(last_event.payload.get(k), v)

    def _add_blueprint(self, session):
        blueprint = Blueprint.objects.create(name=get_random_string(12))
        update_blueprint_activation(blueprint, commit=False)
        update_blueprint_declaration_items(blueprint)
        session.enrolled_device.blueprint = blueprint
        session.enrolled_device.save()
        return blueprint

    # checkin - authenticate

    def test_unknown_message_type(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(self.mbu)
        response = self._put(reverse("mdm:checkin"), {"UDID": udid, "MessageType": "yolo"}, session)
        self.assertEqual(response.status_code, 400)
        self._assertAbort(post_event, "unknown message type", udid=udid, serial_number=serial_number)

    def test_unknown_topic(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(self.mbu)
        topic = get_random_string()
        payload = {
            "UDID": udid,
            "SerialNumber": serial_number,
            # No UserID or EnrollmentUserID → Device Channel
            "MessageType": "Authenticate",
            "Topic": topic,
            "DeviceName": get_random_string(),
            "Model": "Macmini9,1",
            "ModelName": "Mac mini",
            "OSVersion": "12.4",
            "BuildVersion": "21F79",
        }
        response = self._put(reverse("mdm:checkin"), payload, session)
        self.assertEqual(response.status_code, 400)
        self._assertAbort(post_event, "unknown topic", topic=topic)

    def test_authenticate_dep_enrollment_session_macos(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(self.mbu)
        self.assertEqual(session.status, DEPEnrollmentSession.STARTED)
        self.assertIsNone(session.enrolled_device)
        payload = {
            "UDID": udid,
            "SerialNumber": serial_number,
            # No UserID or EnrollmentUserID → Device Channel
            "MessageType": "Authenticate",
            "Topic": session.get_enrollment().push_certificate.topic,
            "DeviceName": get_random_string(),
            "Model": "Macmini9,1",
            "ModelName": "Mac mini",
            "OSVersion": "12.4",
            "BuildVersion": "21F79",
        }
        response = self._put(reverse("mdm:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        self._assertSuccess(post_event, new_enrolled_device=True, reenrollment=False)
        session.refresh_from_db()
        self.assertEqual(session.status, DEPEnrollmentSession.AUTHENTICATED)
        self.assertEqual(session.enrolled_device.udid, udid)
        self.assertEqual(session.enrolled_device.serial_number, serial_number)
        self.assertEqual(session.enrolled_device.cert_not_valid_after, datetime(2034, 5, 6))
        self.assertEqual(session.enrolled_device.platform, "macOS")
        self.assertTrue(session.enrolled_device.dep_enrollment)
        self.assertTrue(session.enrolled_device.user_enrollment is False)
        self.assertTrue(session.enrolled_device.user_approved_enrollment)
        self.assertTrue(session.enrolled_device.supervised)

    def test_authenticate_dep_enrollment_session_ios(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(self.mbu)
        self.assertEqual(session.status, DEPEnrollmentSession.STARTED)
        self.assertIsNone(session.enrolled_device)
        payload = {
            "UDID": udid,
            "SerialNumber": serial_number,
            # No UserID or EnrollmentUserID → Device Channel
            "MessageType": "Authenticate",
            "Topic": session.get_enrollment().push_certificate.topic,
            "DeviceName": get_random_string(),
            "Model": "iPhone13",
            "ModelName": "iPhone",
            "OSVersion": "16.2",
            "BuildVersion": "20C65",
        }
        response = self._put(reverse("mdm:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        self._assertSuccess(post_event, new_enrolled_device=True, reenrollment=False)
        session.refresh_from_db()
        self.assertEqual(session.status, DEPEnrollmentSession.AUTHENTICATED)
        self.assertEqual(session.enrolled_device.udid, udid)
        self.assertEqual(session.enrolled_device.serial_number, serial_number)
        self.assertEqual(session.enrolled_device.cert_not_valid_after, datetime(2034, 5, 6))
        self.assertEqual(session.enrolled_device.platform, "iOS")
        self.assertTrue(session.enrolled_device.dep_enrollment)
        self.assertTrue(session.enrolled_device.user_enrollment is False)
        self.assertIsNone(session.enrolled_device.user_approved_enrollment)
        self.assertTrue(session.enrolled_device.supervised)

    def test_authenticate_ota_enrollment_session_macos(self, post_event):
        session, device_udid, serial_number = force_ota_enrollment_session(self.mbu, phase3=True)
        self.assertEqual(session.status, OTAEnrollmentSession.PHASE_3)
        self.assertIsNone(session.enrolled_device)
        payload = {
            "UDID": device_udid,
            "SerialNumber": serial_number,
            # No UserID or EnrollmentUserID → Device Channel
            "MessageType": "Authenticate",
            "Topic": session.get_enrollment().push_certificate.topic,
            "DeviceName": get_random_string(),
            "Model": "Macmini9,1",
            "ModelName": "Mac mini",
            "OSVersion": "12.4",
            "BuildVersion": "21F79",
        }
        response = self._put(reverse("mdm:checkin"), payload, session, serial_number=serial_number)
        self.assertEqual(response.status_code, 200)
        self._assertSuccess(post_event, new_enrolled_device=True, reenrollment=False)
        session.refresh_from_db()
        self.assertEqual(session.status, OTAEnrollmentSession.AUTHENTICATED)
        self.assertEqual(session.enrolled_device.udid, device_udid)
        self.assertEqual(session.enrolled_device.serial_number, serial_number)
        self.assertEqual(session.enrolled_device.cert_not_valid_after, datetime(2034, 5, 6))
        self.assertEqual(session.enrolled_device.platform, "macOS")
        self.assertTrue(session.enrolled_device.dep_enrollment is False)
        self.assertTrue(session.enrolled_device.user_enrollment is False)
        self.assertIsNone(session.enrolled_device.user_approved_enrollment)
        self.assertIsNone(session.enrolled_device.supervised)

    def test_authenticate_user_enrollment_session_macos(self, post_event):
        session, _, _ = force_user_enrollment_session(self.mbu)
        self.assertEqual(session.status, UserEnrollmentSession.STARTED)
        self.assertIsNone(session.enrolled_device)
        device_udid = get_random_string(12)
        serial_number = get_random_string(12)
        payload = {
            "UDID": device_udid,
            "SerialNumber": serial_number,
            # No UserID or EnrollmentUserID → Device Channel
            "MessageType": "Authenticate",
            "Topic": session.get_enrollment().push_certificate.topic,
            "DeviceName": get_random_string(),
            "Model": "Macmini9,1",
            "ModelName": "Mac mini",
            "OSVersion": "12.4",
            "BuildVersion": "21F79",
        }
        response = self._put(reverse("mdm:checkin"), payload, session, serial_number=serial_number)
        self.assertEqual(response.status_code, 200)
        self._assertSuccess(post_event, new_enrolled_device=True, reenrollment=False)
        session.refresh_from_db()
        self.assertEqual(session.status, UserEnrollmentSession.AUTHENTICATED)
        self.assertEqual(session.enrolled_device.udid, device_udid)
        self.assertEqual(session.enrolled_device.serial_number, serial_number)
        self.assertEqual(session.enrolled_device.cert_not_valid_after, datetime(2034, 5, 6))
        self.assertEqual(session.enrolled_device.platform, "macOS")
        self.assertTrue(session.enrolled_device.dep_enrollment is False)
        self.assertTrue(session.enrolled_device.user_enrollment)
        self.assertIsNone(session.enrolled_device.user_approved_enrollment)
        self.assertTrue(session.enrolled_device.supervised is False)

    def test_authenticate_new_enrollment_purged_state(self, post_event):
        # get a fully enrolled device
        session, udid, serial_number = force_dep_enrollment_session(self.mbu, authenticated=True, completed=True)
        # simulate some state
        ed = session.enrolled_device
        self.assertIsNone(ed.last_seen_at)
        self.assertIsNone(ed.last_notified_at)
        self.assertIsNone(ed.notification_queued_at)
        ed.last_seen_at = datetime.utcnow()
        ed.last_notified_at = datetime.utcnow()
        ed.notification_queued_at = datetime.utcnow()
        ed.save()
        # new enrollment but not a re-enrollment session
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, device_udid=udid, serial_number=serial_number
        )
        payload = {
            "UDID": udid,
            "SerialNumber": serial_number,
            # No UserID or EnrollmentUserID → Device Channel
            "MessageType": "Authenticate",
            "Topic": session.get_enrollment().push_certificate.topic,
            "DeviceName": get_random_string(),
            "Model": "Macmini9,1",
            "ModelName": "Mac mini",
            "OSVersion": "12.4",
            "BuildVersion": "21F79",
        }
        response = self._put(reverse("mdm:checkin"), payload, session)
        self._assertSuccess(post_event, new_enrolled_device=False, reenrollment=False)
        self.assertEqual(response.status_code, 200)
        session.refresh_from_db()
        ed.refresh_from_db()
        self.assertEqual(session.enrolled_device, ed)
        self.assertIsNone(ed.last_seen_at)
        self.assertIsNone(ed.last_notified_at)
        self.assertIsNone(ed.notification_queued_at)

    # checkin - token update

    def test_device_channel_token_update_no_awaiting_configuration(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(self.mbu, authenticated=True)
        self.assertEqual(session.status, DEPEnrollmentSession.AUTHENTICATED)
        push_magic = get_random_string(12)
        token = get_random_string(12).encode("utf-8")
        unlock_token = get_random_string(12).encode("utf-8")
        payload = {
            "UDID": udid,
            # No UserID or EnrollmentUserID → Device Channel
            "MessageType": "TokenUpdate",
            "AwaitingConfiguration": False,
            "NotOnConsole": False,
            "PushMagic": push_magic,
            "Token": token,
            "Topic": session.get_enrollment().push_certificate.topic,
            "UnlockToken": unlock_token,
        }
        response = self._put(reverse("mdm:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        self._assertSuccess(post_event, token_type="device", device_created=False, user_created=False)
        session.refresh_from_db()
        self.assertEqual(session.status, DEPEnrollmentSession.COMPLETED)
        self.assertEqual(session.enrolled_device.push_magic, push_magic)
        self.assertEqual(session.enrolled_device.token.tobytes(), token)
        self.assertEqual(session.enrolled_device.get_unlock_token(), unlock_token)
        self.assertIsNone(session.enrolled_device.bootstrap_token)

    def test_user_channel_token_update(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(self.mbu, authenticated=True, completed=True)
        self.assertEqual(session.status, DEPEnrollmentSession.COMPLETED)
        user_id = str(uuid.uuid4())
        token = get_random_string(12).encode("utf-8")
        user_long_name = get_random_string(42)
        user_short_name = get_random_string(12)
        payload = {
            "UDID": udid,
            "UserID": user_id,  # → User channel
            "MessageType": "TokenUpdate",
            "AwaitingConfiguration": False,
            "NotOnConsole": False,
            "PushMagic": session.enrolled_device.push_magic,
            "Topic": session.get_enrollment().push_certificate.topic,
            "Token": token,
            "UserLongName": user_long_name,
            "UserShortName": user_short_name,
        }
        response = self._put(reverse("mdm:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        self._assertSuccess(post_event, token_type="user", device_created=False, user_created=True)
        enrolled_user = session.enrolled_device.enrolleduser_set.first()
        self.assertEqual(enrolled_user.user_id, user_id)
        self.assertEqual(enrolled_user.token.tobytes(), token)
        self.assertEqual(enrolled_user.long_name, user_long_name)
        self.assertEqual(enrolled_user.short_name, user_short_name)

    # checkin - set bootstrap token

    def test_set_bootstrap_token_no_awaiting_configuration(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(self.mbu, authenticated=True, completed=True)
        bootstrap_token = get_random_string(12).encode("utf-8")
        payload = {
            "UDID": udid,
            "MessageType": "SetBootstrapToken",
            "AwaitingConfiguration": False,
            "BootstrapToken": bootstrap_token,
        }
        response = self._put(reverse("mdm:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        self._assertSuccess(post_event)
        session.refresh_from_db()
        self.assertEqual(session.enrolled_device.get_bootstrap_token(), bootstrap_token)

    # checkin - get bootstrap token

    def test_get_bootstrap_token_error(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(self.mbu, authenticated=True, completed=True)
        payload = {
            "UDID": udid,
            "MessageType": "GetBootstrapToken",
        }
        response = self._put(reverse("mdm:checkin"), payload, session)
        self.assertEqual(response.status_code, 400)
        self._assertAbort(post_event, f"Enrolled device {udid} has no bootstrap token")

    def test_get_bootstrap_token(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(self.mbu, authenticated=True, completed=True)
        bootstrap_token = get_random_string(12).encode("utf-8")
        session.enrolled_device.set_bootstrap_token(bootstrap_token)
        session.enrolled_device.save()
        payload = {
            "UDID": udid,
            "MessageType": "GetBootstrapToken",
        }
        response = self._put(reverse("mdm:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        self._assertSuccess(post_event)
        data = plistlib.loads(response.content)
        self.assertEqual(data["BootstrapToken"], bootstrap_token)

    # checkin - declarative management

    def test_declarative_management_no_blueprint_error(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(self.mbu, authenticated=True, completed=True)
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": "declaration-items"
        }
        response = self._put(reverse("mdm:checkin"), payload, session)
        self.assertEqual(response.status_code, 400)
        self._assertAbort(post_event, "Missing blueprint. No declarative management possible.",
                          data={"un": 2}, endpoint="declaration-items")

    def test_declarative_management_tokens(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(self.mbu, authenticated=True, completed=True)
        blueprint = self._add_blueprint(session)
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": "tokens"
        }
        response = self._put(reverse("mdm:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.content)
        tokens_response, declarations_token = get_blueprint_tokens_response(blueprint)
        self.assertEqual(json_response, tokens_response)
        self._assertSuccess(post_event, endpoint="tokens")
        session.enrolled_device.refresh_from_db()
        self.assertEqual(session.enrolled_device.declarations_token, declarations_token)

    # checking - checkout

    def test_checkout(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(self.mbu, authenticated=True, completed=True)
        enrolled_device = session.enrolled_device
        self.assertIsNone(enrolled_device.checkout_at)
        payload = {
            "UDID": udid,
            "MessageType": "CheckOut",
            "Topic": session.get_enrollment().push_certificate.topic,
        }
        response = self._put(reverse("mdm:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        self._assertSuccess(post_event)
        enrolled_device.refresh_from_db()
        self.assertIsNone(enrolled_device.token)
        self.assertIsNone(enrolled_device.push_magic)
        self.assertIsNone(enrolled_device.get_bootstrap_token())
        self.assertIsNone(enrolled_device.get_unlock_token())
        self.assertIsNotNone(enrolled_device.checkout_at)

    # connect

    def test_device_channel_connect_idle_no_command(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(self.mbu, authenticated=True, completed=True)
        now = datetime.utcnow()
        enrolled_device = EnrolledDevice.objects.get(udid=udid)
        self.assertIsNone(enrolled_device.last_seen_at)
        payload = {"UDID": udid, "Status": "Idle"}
        response = self._put(reverse("mdm:connect"), payload, session)
        self.assertEqual(response.content, b"")
        self.assertEqual(response.status_code, 200)
        enrolled_device.refresh_from_db()
        self.assertTrue(enrolled_device.last_seen_at > now)

    def test_user_channel_connect_idle_no_command(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(self.mbu, authenticated=True, completed=True)
        enrolled_user = force_enrolled_user(session.enrolled_device)
        self.assertIsNone(enrolled_user.last_seen_at)
        now = datetime.utcnow()
        payload = {"UDID": udid, "Status": "Idle",
                   "UserID": enrolled_user.user_id}
        response = self._put(reverse("mdm:connect"), payload, session)
        self.assertEqual(response.content, b"")
        self.assertEqual(response.status_code, 200)
        enrolled_user.refresh_from_db()
        self.assertTrue(enrolled_user.last_seen_at > now)

    def test_device_channel_connect_idle_device_cert_expiry_reenroll(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(self.mbu, authenticated=True, completed=True)
        session.enrolled_device.cert_not_valid_after = datetime.utcnow() + timedelta(days=1)
        session.enrolled_device.save()
        payload = {"UDID": udid, "Status": "Idle"}
        response = self._put(reverse("mdm:connect"), payload, session)
        self.assertEqual(response.status_code, 200)
        data = plistlib.loads(response.content)
        self.assertEqual(data["Command"]["RequestType"], "InstallProfile")
        command_uuid = data["CommandUUID"]
        db_command = DeviceCommand.objects.get(uuid=command_uuid)
        self.assertEqual(db_command.name, "Reenroll")
        self.assertEqual(db_command.enrolled_device, session.enrolled_device)
        certificates, profile_data = verify_signed_payload(data["Command"]["Payload"])
        profile = plistlib.loads(profile_data)
        mdm_payload = scep_payload = None
        for payload in profile["PayloadContent"]:
            payload_type = payload["PayloadType"]
            if payload_type == "com.apple.security.scep":
                scep_payload = payload
            elif payload_type == "com.apple.mdm":
                mdm_payload = payload
        resession = ReEnrollmentSession.objects.filter(enrolled_device__udid=udid).order_by("-pk").first()
        self.assertEqual(mdm_payload["IdentityCertificateUUID"], scep_payload["PayloadUUID"])
        self.assertEqual(scep_payload["PayloadContent"]["Subject"][0][0],
                         ["CN", f"MDM$RE${resession.enrollment_secret.secret}"])

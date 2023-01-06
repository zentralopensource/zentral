from datetime import datetime, timedelta
import plistlib
from unittest.mock import patch
import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.commands import Reenroll
from zentral.contrib.mdm.commands.scheduling import _reenroll
from zentral.contrib.mdm.models import (
    Channel,
    EnrolledUser,
    Platform,
    RequestStatus,
    ReEnrollmentSession,
)
from .utils import force_dep_enrollment_session


class ReenrollCommandTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.dep_enrollment_session, _, _ = force_dep_enrollment_session(
            cls.mbu, authenticated=True, completed=True, realm_user=True
        )
        cls.dep_enrollment = cls.dep_enrollment_session.dep_enrollment
        cls.enrolled_device = cls.dep_enrollment_session.enrolled_device
        cls.enrolled_user = EnrolledUser.objects.create(
            enrolled_device=cls.enrolled_device,
            user_id=str(uuid.uuid4()).upper(),
            long_name=get_random_string(12),
            short_name=get_random_string(12),
            token=get_random_string(12).encode("utf-8"),
        )

    # verify_channel_and_device

    def test_scope(self):
        for channel, platform, user_enrollment, result in (
            (Channel.Device, Platform.iOS, False, True),
            (Channel.Device, Platform.iPadOS, False, True),
            (Channel.Device, Platform.macOS, False, True),
            (Channel.Device, Platform.tvOS, False, True),
            (Channel.User, Platform.iOS, False, False),
            (Channel.User, Platform.iPadOS, False, False),
            (Channel.User, Platform.macOS, False, False),
            (Channel.User, Platform.tvOS, False, False),
            (Channel.Device, Platform.iOS, True, True),
            (Channel.Device, Platform.iPadOS, True, True),
            (Channel.Device, Platform.macOS, True, True),
            (Channel.Device, Platform.tvOS, True, True),
            (Channel.User, Platform.iOS, True, False),
            (Channel.User, Platform.iPadOS, True, False),
            (Channel.User, Platform.macOS, True, False),
            (Channel.User, Platform.tvOS, True, False),
        ):
            self.enrolled_device.platform = platform.name
            self.enrolled_device.user_enrollment = user_enrollment
            self.assertEqual(
                result,
                Reenroll.verify_channel_and_device(channel, self.enrolled_device),
            )

    # load_kwargs

    @patch("zentral.contrib.mdm.commands.base.uuid.uuid4")
    def test_load_kwargs_missing_session_id(self, uuid4):
        uuid4.return_value = uuid.UUID("820e2bda-0e94-4557-a0ff-9bf000f22f51")
        with self.assertRaises(ValueError) as cm:
            Reenroll.create_for_device(self.enrolled_device)
        self.assertEqual(
            cm.exception.args[0],
            "Command 820e2bda-0e94-4557-a0ff-9bf000f22f51: could not find session id",
        )

    @patch("zentral.contrib.mdm.commands.base.uuid.uuid4")
    def test_load_kwargs_unknown_session_(self, uuid4):
        uuid4.return_value = uuid.UUID("820e2bda-0e94-4557-a0ff-9bf000f22f52")
        with self.assertRaises(ValueError) as cm:
            Reenroll.create_for_device(self.enrolled_device, kwargs={"session_id": 0})
        self.assertEqual(
            cm.exception.args[0],
            "Command 820e2bda-0e94-4557-a0ff-9bf000f22f52: could not find re-enrollment session 0",
        )

    # build_command

    @patch("zentral.contrib.mdm.payloads.sign_payload")
    def test_build_command(self, sign_payload):
        sign_payload.side_effect = lambda a: a  # bypass payload signature
        cmd = Reenroll.create_for_enrollment_session(self.dep_enrollment_session)
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(payload["RequestType"], "InstallProfile")
        payloadPayload = payload["Payload"]
        sign_payload.assert_called_once_with(payloadPayload)
        loadedPayloadPayload = plistlib.loads(payloadPayload)
        self.assertEqual(loadedPayloadPayload["PayloadIdentifier"], "zentral.mdm")
        self.assertEqual(loadedPayloadPayload["PayloadType"], "Configuration")
        self.assertEqual(
            [pc["PayloadType"] for pc in loadedPayloadPayload["PayloadContent"]],
            ["com.apple.security.pem",
             "com.apple.security.scep",
             "com.apple.mdm"]
        )

    # _reenroll

    def test_reenroll_user_channel_noop(self):
        self.assertIsNone(
            _reenroll(
                Channel.User,
                RequestStatus.Idle,
                self.dep_enrollment_session,
                self.enrolled_device,
                self.enrolled_user,
            )
        )

    def test_reenroll_device_channel_notnow_noop(self):
        self.assertIsNone(
            _reenroll(
                Channel.Device,
                RequestStatus.NotNow,
                self.dep_enrollment_session,
                self.enrolled_device,
                self.enrolled_user,
            )
        )

    def test_reenroll_device_channel_no_cert_not_valid_after(self):
        self.enrolled_device.cert_not_valid_after = None
        command = _reenroll(
            Channel.Device,
            RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            self.enrolled_user,
        )
        self.assertIsInstance(command, Reenroll)
        self.assertIsInstance(command.reenrollment_session, ReEnrollmentSession)
        self.assertEqual(
            command.reenrollment_session.get_enrollment(), self.dep_enrollment
        )
        self.assertEqual(
            command.reenrollment_session.enrolled_device, self.enrolled_device
        )

    def test_reenroll_device_channel_no_cert_not_valid_after_recent_reenrollment_session_noop(self):
        self.enrolled_device.cert_not_valid_after = None
        ReEnrollmentSession.objects.create_from_enrollment_session(
            self.dep_enrollment_session
        )
        self.assertIsNone(
            _reenroll(
                Channel.Device,
                RequestStatus.Idle,
                self.dep_enrollment_session,
                self.enrolled_device,
                self.enrolled_user,
            )
        )

    def test_reenroll_device_channel_cert_too_old(self):
        self.enrolled_device.cert_not_valid_after = datetime.utcnow() + timedelta(days=10)
        self.enrolled_device.save()
        command = _reenroll(
            Channel.Device,
            RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            self.enrolled_user,
        )
        self.assertIsInstance(command, Reenroll)
        self.assertIsInstance(command.reenrollment_session, ReEnrollmentSession)
        self.assertEqual(
            command.reenrollment_session.get_enrollment(), self.dep_enrollment
        )
        self.assertEqual(
            command.reenrollment_session.enrolled_device, self.enrolled_device
        )

    def test_reenroll_device_channel_cert_too_old_recent_reenrollment_session_noop(self):
        self.enrolled_device.cert_not_valid_after = datetime.utcnow()
        self.enrolled_device.save()
        ReEnrollmentSession.objects.create_from_enrollment_session(
            self.dep_enrollment_session
        )
        self.assertIsNone(
            _reenroll(
                Channel.Device,
                RequestStatus.Idle,
                self.dep_enrollment_session,
                self.enrolled_device,
                self.enrolled_user,
            )
        )

    def test_reenroll_device_channel_cert_too_old_older_reenrollment_session(self):
        self.enrolled_device.cert_not_valid_after = datetime.utcnow()
        self.enrolled_device.save()
        rs = ReEnrollmentSession.objects.create_from_enrollment_session(
            self.dep_enrollment_session
        )
        ReEnrollmentSession.objects.filter(pk=rs.pk).update(
            created_at=datetime.utcnow() - timedelta(hours=8)
        )
        command = _reenroll(
            Channel.Device,
            RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            self.enrolled_user,
        )
        self.assertIsInstance(command, Reenroll)
        self.assertIsInstance(command.reenrollment_session, ReEnrollmentSession)
        self.assertEqual(
            command.reenrollment_session.get_enrollment(), self.dep_enrollment
        )
        self.assertEqual(
            command.reenrollment_session.enrolled_device, self.enrolled_device
        )

    def test_reenroll_device_channel_cert_ok_noop(self):
        self.enrolled_device.cert_not_valid_after = datetime.utcnow() + timedelta(days=167)
        self.enrolled_device.save()
        self.assertIsNone(
            _reenroll(
                Channel.Device,
                RequestStatus.Idle,
                self.dep_enrollment_session,
                self.enrolled_device,
                self.enrolled_user,
            )
        )

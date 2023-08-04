from datetime import datetime, timedelta
import plistlib
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import load_der_x509_certificate
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.commands import RotateFileVaultKey
from zentral.contrib.mdm.commands.scheduling import _rotate_filevault_key
from zentral.contrib.mdm.crypto import encrypt_cms_payload
from zentral.contrib.mdm.events import FileVaultPRKUpdatedEvent
from zentral.contrib.mdm.models import Channel, Command, Platform, RequestStatus
from .utils import force_blueprint, force_dep_enrollment_session, force_filevault_config


class RotateFileVaultKeyCommandTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.dep_enrollment_session, cls.device_udid, cls.serial_number = force_dep_enrollment_session(
            cls.mbu,
            authenticated=True,
            completed=True,
        )
        cls.enrolled_device = cls.dep_enrollment_session.enrolled_device

    # verify_channel_and_device

    def test_verify_channel_and_device_ok(self):
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.enrolled_device.user_enrollment = False
        self.enrolled_device.set_filevault_prk("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
        self.assertTrue(RotateFileVaultKey.verify_channel_and_device(
            Channel.DEVICE,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_user_channel_not_ok(self):
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.enrolled_device.user_enrollment = False
        self.enrolled_device.set_filevault_prk("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
        self.assertFalse(RotateFileVaultKey.verify_channel_and_device(
            Channel.USER,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_ios_not_ok(self):
        self.enrolled_device.platform = Platform.IOS
        self.enrolled_device.user_enrollment = False
        self.enrolled_device.set_filevault_prk("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
        self.assertFalse(RotateFileVaultKey.verify_channel_and_device(
            Channel.DEVICE,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_user_enrollment_not_ok(self):
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.enrolled_device.user_enrollment = True
        self.enrolled_device.set_filevault_prk("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
        self.assertFalse(RotateFileVaultKey.verify_channel_and_device(
            Channel.DEVICE,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_no_filevault_prk_not_ok(self):
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.enrolled_device.user_enrollment = False
        self.assertFalse(RotateFileVaultKey.verify_channel_and_device(
            Channel.DEVICE,
            self.enrolled_device
        ))

    # build_command

    def test_build_command(self):
        self.enrolled_device.user_enrollment = False
        self.enrolled_device.set_filevault_prk("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
        cmd = RotateFileVaultKey.create_for_target(Target(self.enrolled_device))
        response = cmd.build_http_response(self.dep_enrollment_session)
        cmd_plist = plistlib.loads(response.content)["Command"]
        self.assertEqual(cmd_plist["RequestType"], "RotateFileVaultKey")
        self.assertEqual(cmd_plist["KeyType"], "personal")
        self.assertEqual(cmd_plist["FileVaultUnlock"], {"Password": "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"})
        cert = load_der_x509_certificate(cmd_plist["ReplyEncryptionCertificate"])
        privkey = cmd.load_encryption_key()
        privkey.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )

    # process_response

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_process_acknowledged_response(self, post_event):
        self.enrolled_device.user_enrollment = False
        self.enrolled_device.set_filevault_prk("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
        self.enrolled_device.save()
        cmd = RotateFileVaultKey.create_for_target(Target(self.enrolled_device))
        response = cmd.build_http_response(self.dep_enrollment_session)
        cmd_plist = plistlib.loads(response.content)["Command"]
        cert = load_der_x509_certificate(cmd_plist["ReplyEncryptionCertificate"])
        cert_bytes = cert.public_bytes(encoding=Encoding.PEM)
        with self.captureOnCommitCallbacks(execute=True):
            cmd.process_response(
                {"UDID": self.enrolled_device.udid,
                 "Status": "Acknowledged",
                 "CommandUUID": str(cmd.uuid).upper(),
                 "RotateResult": {"EncryptedNewRecoveryKey": encrypt_cms_payload(b"BBBB-BBBB-BBBB-BBBB-BBBB-BBBB",
                                                                                 cert_bytes,
                                                                                 raw_output=True)}},
                self.dep_enrollment_session,
                self.mbu
            )
        cmd.db_command.refresh_from_db()
        self.assertEqual(cmd.status, Command.Status.ACKNOWLEDGED)
        self.assertEqual(cmd.db_command.status, Command.Status.ACKNOWLEDGED)
        self.enrolled_device.refresh_from_db()
        self.assertEqual(self.enrolled_device.get_filevault_prk(), "BBBB-BBBB-BBBB-BBBB-BBBB-BBBB")
        # event
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, FileVaultPRKUpdatedEvent)
        self.assertEqual(
            event.payload,
            {'command': {'request_type': 'RotateFileVaultKey',
             'uuid': str(cmd.uuid)}}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["machine_serial_number"], self.enrolled_device.serial_number)
        self.assertEqual(metadata["objects"], {"mdm_command": [str(cmd.uuid)]})
        self.assertEqual(metadata["tags"], ["mdm"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_process_acknowledged_cms_error_response(self, post_event):
        self.enrolled_device.user_enrollment = False
        self.enrolled_device.set_filevault_prk("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
        self.enrolled_device.save()
        cmd = RotateFileVaultKey.create_for_target(Target(self.enrolled_device))
        with self.captureOnCommitCallbacks(execute=True):
            cmd.process_response(
                {"UDID": self.enrolled_device.udid,
                 "Status": "Acknowledged",
                 "CommandUUID": str(cmd.uuid).upper(),
                 "RotateResult": {"EncryptedNewRecoveryKey": b"not a cms payload"}},
                self.dep_enrollment_session,
                self.mbu
            )
        cmd.db_command.refresh_from_db()
        self.assertEqual(cmd.status, Command.Status.ACKNOWLEDGED)
        self.assertEqual(cmd.db_command.status, Command.Status.ACKNOWLEDGED)
        self.enrolled_device.refresh_from_db()
        self.assertEqual(self.enrolled_device.get_filevault_prk(), "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
        # no events
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_process_acknowledged_no_change_response(self, post_event):
        self.enrolled_device.user_enrollment = False
        self.enrolled_device.set_filevault_prk("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
        self.enrolled_device.save()
        cmd = RotateFileVaultKey.create_for_target(Target(self.enrolled_device))
        response = cmd.build_http_response(self.dep_enrollment_session)
        cmd_plist = plistlib.loads(response.content)["Command"]
        cert = load_der_x509_certificate(cmd_plist["ReplyEncryptionCertificate"])
        cert_bytes = cert.public_bytes(encoding=Encoding.PEM)
        with self.captureOnCommitCallbacks(execute=True):
            cmd.process_response(
                {"UDID": self.enrolled_device.udid,
                 "Status": "Acknowledged",
                 "CommandUUID": str(cmd.uuid).upper(),
                 "RotateResult": {"EncryptedNewRecoveryKey": encrypt_cms_payload(b"AAAA-AAAA-AAAA-AAAA-AAAA-AAAA",
                                                                                 cert_bytes,
                                                                                 raw_output=True)}},
                self.dep_enrollment_session,
                self.mbu
            )
        cmd.db_command.refresh_from_db()
        self.assertEqual(cmd.status, Command.Status.ACKNOWLEDGED)
        self.assertEqual(cmd.db_command.status, Command.Status.ACKNOWLEDGED)
        self.enrolled_device.refresh_from_db()
        self.assertEqual(self.enrolled_device.get_filevault_prk(), "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
        # no events
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 0)

    # _rotate_filevault_key

    def test_rotate_filevault_key_notnow_noop(self):
        self.enrolled_device.user_enrollment = False
        self.enrolled_device.set_filevault_prk("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
        self.assertIsNone(_rotate_filevault_key(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.NOT_NOW,
        ))

    def test_rotate_filevault_key_target_not_ok_noop(self):
        target = Target(self.enrolled_device)
        self.assertFalse(RotateFileVaultKey.verify_target(target))
        self.assertIsNone(_rotate_filevault_key(
            target,
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_rotate_filevault_key_no_filevault_config_noop(self):
        self.enrolled_device.user_enrollment = False
        self.enrolled_device.set_filevault_prk("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
        self.assertIsNone(_rotate_filevault_key(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_rotate_filevault_key_rotation_interval_days_zero_noop(self):
        self.enrolled_device.user_enrollment = False
        self.enrolled_device.set_filevault_prk("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
        filevault_config = force_filevault_config()
        self.assertEqual(filevault_config.prk_rotation_interval_days, 0)
        self.enrolled_device.blueprint = force_blueprint(filevault_config=filevault_config)
        self.assertIsNone(_rotate_filevault_key(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_rotate_filevault_key_rotation_last_within_interval_days_noop(self):
        self.enrolled_device.user_enrollment = False
        self.enrolled_device.set_filevault_prk("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
        filevault_config = force_filevault_config()
        filevault_config.prk_rotation_interval_days = 90
        self.enrolled_device.blueprint = force_blueprint(filevault_config=filevault_config)
        self.enrolled_device.filevault_prk_updated_at = datetime.utcnow() - timedelta(days=89)
        self.assertIsNone(_rotate_filevault_key(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_rotate_filevault_key_recent_failed_command_noop(self):
        self.enrolled_device.user_enrollment = False
        self.enrolled_device.set_filevault_prk("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
        filevault_config = force_filevault_config()
        filevault_config.prk_rotation_interval_days = 90
        self.enrolled_device.blueprint = force_blueprint(filevault_config=filevault_config)
        self.enrolled_device.filevault_prk_updated_at = datetime.utcnow() - timedelta(days=91)
        cmd = RotateFileVaultKey.create_for_target(Target(self.enrolled_device))
        cmd.process_response(
            {"UDID": self.enrolled_device.udid,
             "Status": "Error",
             "CommandUUID": str(cmd.uuid).upper()},
            self.dep_enrollment_session,
            self.mbu
        )
        self.assertIsNone(_rotate_filevault_key(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_rotate_filevault_key_old_failed_command_ok(self):
        self.enrolled_device.user_enrollment = False
        self.enrolled_device.set_filevault_prk("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
        filevault_config = force_filevault_config()
        filevault_config.prk_rotation_interval_days = 90
        self.enrolled_device.blueprint = force_blueprint(filevault_config=filevault_config)
        self.enrolled_device.filevault_prk_updated_at = datetime.utcnow() - timedelta(days=91)
        cmd = RotateFileVaultKey.create_for_target(Target(self.enrolled_device))
        cmd.db_command.time = datetime.utcnow() - timedelta(hours=5)
        cmd.db_command.save()
        cmd.process_response(
            {"UDID": self.enrolled_device.udid,
             "Status": "Error",
             "CommandUUID": str(cmd.uuid).upper()},
            self.dep_enrollment_session,
            self.mbu
        )
        cmd = _rotate_filevault_key(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(cmd, RotateFileVaultKey)

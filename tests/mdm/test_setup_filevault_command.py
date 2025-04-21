from datetime import datetime, timedelta
import plistlib
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.x509 import load_der_x509_certificate
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.commands import SecurityInfo, SetupFileVault
from zentral.contrib.mdm.commands.base import load_command
from zentral.contrib.mdm.commands.scheduling import _get_next_queued_command, _setup_filevault
from zentral.contrib.mdm.models import Channel, Command, DeviceCommand, Platform, RequestStatus
from .utils import force_blueprint, force_dep_enrollment_session, force_filevault_config


class SetupFileVaultCommandTestCase(TestCase):
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
        self.enrolled_device.user_approved_enrollment = True
        self.enrolled_device.user_enrollment = False
        filevault_config = force_filevault_config()
        self.enrolled_device.blueprint = force_blueprint(filevault_config=filevault_config)
        self.assertTrue(SetupFileVault.verify_channel_and_device(
            Channel.DEVICE,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_user_channel_not_ok(self):
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.enrolled_device.user_approved_enrollment = True
        self.enrolled_device.user_enrollment = False
        filevault_config = force_filevault_config()
        self.enrolled_device.blueprint = force_blueprint(filevault_config=filevault_config)
        self.assertFalse(SetupFileVault.verify_channel_and_device(
            Channel.USER,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_ios_not_ok(self):
        self.enrolled_device.platform = Platform.IOS
        self.enrolled_device.user_approved_enrollment = True
        self.enrolled_device.user_enrollment = False
        filevault_config = force_filevault_config()
        self.enrolled_device.blueprint = force_blueprint(filevault_config=filevault_config)
        self.assertFalse(SetupFileVault.verify_channel_and_device(
            Channel.DEVICE,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_not_user_approved_enrollment_not_ok(self):
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.enrolled_device.user_approved_enrollment = False
        self.enrolled_device.user_enrollment = False
        filevault_config = force_filevault_config()
        self.enrolled_device.blueprint = force_blueprint(filevault_config=filevault_config)
        self.assertFalse(SetupFileVault.verify_channel_and_device(
            Channel.DEVICE,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_user_enrollment_not_ok(self):
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.enrolled_device.user_approved_enrollment = True
        self.enrolled_device.user_enrollment = True
        filevault_config = force_filevault_config()
        self.enrolled_device.blueprint = force_blueprint(filevault_config=filevault_config)
        self.assertFalse(SetupFileVault.verify_channel_and_device(
            Channel.DEVICE,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_no_blueprint_not_ok(self):
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.enrolled_device.user_approved_enrollment = True
        self.enrolled_device.user_enrollment = False
        self.assertFalse(SetupFileVault.verify_channel_and_device(
            Channel.DEVICE,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_no_filevault_config_not_ok(self):
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.enrolled_device.user_approved_enrollment = True
        self.enrolled_device.user_enrollment = False
        self.enrolled_device.blueprint = force_blueprint()
        self.assertFalse(SetupFileVault.verify_channel_and_device(
            Channel.DEVICE,
            self.enrolled_device
        ))

    # build_command

    @patch("zentral.contrib.mdm.commands.setup_filevault.sign_payload")
    def test_build_command_awaiting_configuration_false(self, sign_payload):
        sign_payload.side_effect = lambda a: a  # bypass payload signature
        self.enrolled_device.user_approved_enrollment = True
        self.enrolled_device.user_enrollment = False
        self.assertFalse(self.enrolled_device.awaiting_configuration)
        self.assertIsNone(self.enrolled_device.filevault_escrow_key)
        filevault_config = force_filevault_config()
        self.enrolled_device.blueprint = force_blueprint(filevault_config=filevault_config)
        cmd = SetupFileVault.create_for_target(Target(self.enrolled_device))
        response = cmd.build_http_response(self.dep_enrollment_session)
        cmd_plist = plistlib.loads(response.content)["Command"]
        self.assertEqual(cmd_plist["RequestType"], "InstallProfile")
        profile = plistlib.loads(cmd_plist["Payload"])
        found_sub_payloads = 0
        escrow_cert_payload_uuid = None
        for sub_payload in profile["PayloadContent"]:
            sub_payload_type = sub_payload["PayloadType"]
            if sub_payload_type == "com.apple.MCX.FileVault2":
                self.assertNotIn("ForceEnableInSetupAssistant", sub_payload)
                self.assertEqual(sub_payload["ShowRecoveryKey"], filevault_config.show_recovery_key)
                self.assertTrue(sub_payload["Defer"])
                self.assertEqual(sub_payload["DeferDontAskAtUserLogout"], filevault_config.at_login_only)
                self.assertEqual(sub_payload["DeferForceAtUserLoginMaxBypassAttempts"],
                                 filevault_config.bypass_attempts)
                self.assertEqual(sub_payload["PayloadIdentifier"], "com.zentral.mdm.fv.configuration")
            elif sub_payload_type == "com.apple.MCX":
                self.assertTrue(sub_payload["dontAllowFDEDisable"])
                self.assertFalse(sub_payload["dontAllowFDEEnable"])
                self.assertEqual(sub_payload["DestroyFVKeyOnStandby"], filevault_config.destroy_key_on_standby)
                self.assertEqual(sub_payload["PayloadIdentifier"], "com.zentral.mdm.fv.options")
            elif sub_payload_type == "com.apple.security.pkcs1":
                self.assertEqual(sub_payload["PayloadIdentifier"], "com.zentral.mdm.fv.certificate")
                escrow_cert_payload_uuid = sub_payload["PayloadUUID"]
                cert = load_der_x509_certificate(sub_payload["PayloadContent"])
                privkey = load_der_private_key(self.enrolled_device.get_filevault_escrow_key(), None)
                privkey.public_key().verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
            elif sub_payload_type == "com.apple.security.FDERecoveryKeyEscrow":
                self.assertEqual(sub_payload["EncryptCertPayloadUUID"], escrow_cert_payload_uuid)
                self.assertEqual(sub_payload["Location"], filevault_config.escrow_location_display_name)
                self.assertEqual(sub_payload["PayloadIdentifier"], "com.zentral.mdm.fv.escrow")
            else:
                continue
            found_sub_payloads += 1
        self.assertEqual(found_sub_payloads, 4)

    @patch("zentral.contrib.mdm.commands.setup_filevault.sign_payload")
    def test_build_command_awaiting_configuration_true_macos_13(self, sign_payload):
        sign_payload.side_effect = lambda a: a  # bypass payload signature
        self.enrolled_device.user_approved_enrollment = True
        self.enrolled_device.user_enrollment = False
        self.enrolled_device.awaiting_configuration = True
        filevault_config = force_filevault_config()
        self.enrolled_device.blueprint = force_blueprint(filevault_config=filevault_config)
        cmd = SetupFileVault.create_for_target(Target(self.enrolled_device))
        response = cmd.build_http_response(self.dep_enrollment_session)
        cmd_plist = plistlib.loads(response.content)["Command"]
        self.assertEqual(cmd_plist["RequestType"], "InstallProfile")
        profile = plistlib.loads(cmd_plist["Payload"])
        found_sub_payloads = 0
        escrow_cert_payload_uuid = None
        for sub_payload in profile["PayloadContent"]:
            sub_payload_type = sub_payload["PayloadType"]
            if sub_payload_type == "com.apple.MCX.FileVault2":
                self.assertNotIn("ForceEnableInSetupAssistant", sub_payload)
                self.assertEqual(sub_payload["ShowRecoveryKey"], filevault_config.show_recovery_key)
                self.assertTrue(sub_payload["Defer"])
                self.assertEqual(sub_payload["DeferDontAskAtUserLogout"], filevault_config.at_login_only)
                self.assertEqual(sub_payload["DeferForceAtUserLoginMaxBypassAttempts"],
                                 filevault_config.bypass_attempts)
                self.assertEqual(sub_payload["PayloadIdentifier"], "com.zentral.mdm.fv.configuration")
            elif sub_payload_type == "com.apple.MCX":
                self.assertTrue(sub_payload["dontAllowFDEDisable"])
                self.assertFalse(sub_payload["dontAllowFDEEnable"])
                self.assertEqual(sub_payload["DestroyFVKeyOnStandby"], filevault_config.destroy_key_on_standby)
                self.assertEqual(sub_payload["PayloadIdentifier"], "com.zentral.mdm.fv.options")
            elif sub_payload_type == "com.apple.security.pkcs1":
                self.assertEqual(sub_payload["PayloadIdentifier"], "com.zentral.mdm.fv.certificate")
                escrow_cert_payload_uuid = sub_payload["PayloadUUID"]
            elif sub_payload_type == "com.apple.security.FDERecoveryKeyEscrow":
                self.assertEqual(sub_payload["EncryptCertPayloadUUID"], escrow_cert_payload_uuid)
                self.assertEqual(sub_payload["Location"], filevault_config.escrow_location_display_name)
                self.assertEqual(sub_payload["PayloadIdentifier"], "com.zentral.mdm.fv.escrow")
            else:
                continue
            found_sub_payloads += 1
        self.assertEqual(found_sub_payloads, 4)

    @patch("zentral.contrib.mdm.commands.setup_filevault.sign_payload")
    def test_build_command_awaiting_configuration_true_macos_14(self, sign_payload):
        sign_payload.side_effect = lambda a: a  # bypass payload signature
        self.enrolled_device.user_approved_enrollment = True
        self.enrolled_device.user_enrollment = False
        self.enrolled_device.awaiting_configuration = True
        self.enrolled_device.os_version = "14.0"
        filevault_config = force_filevault_config()
        self.enrolled_device.blueprint = force_blueprint(filevault_config=filevault_config)
        cmd = SetupFileVault.create_for_target(Target(self.enrolled_device))
        response = cmd.build_http_response(self.dep_enrollment_session)
        cmd_plist = plistlib.loads(response.content)["Command"]
        self.assertEqual(cmd_plist["RequestType"], "InstallProfile")
        profile = plistlib.loads(cmd_plist["Payload"])
        found_sub_payloads = 0
        escrow_cert_payload_uuid = None
        for sub_payload in profile["PayloadContent"]:
            sub_payload_type = sub_payload["PayloadType"]
            if sub_payload_type == "com.apple.MCX.FileVault2":
                self.assertTrue(sub_payload["ForceEnableInSetupAssistant"])
                self.assertEqual(sub_payload["ShowRecoveryKey"], filevault_config.show_recovery_key)
                self.assertTrue(sub_payload["Defer"])  # macOS 14.4 workaround
                self.assertNotIn("DeferDontAskAtUserLogout", sub_payload)
                self.assertNotIn("DeferForceAtUserLoginMaxBypassAttempts", sub_payload)
                self.assertEqual(sub_payload["PayloadIdentifier"], "com.zentral.mdm.fv.configuration")
            elif sub_payload_type == "com.apple.MCX":
                self.assertTrue(sub_payload["dontAllowFDEDisable"])
                self.assertFalse(sub_payload["dontAllowFDEEnable"])
                self.assertEqual(sub_payload["DestroyFVKeyOnStandby"], filevault_config.destroy_key_on_standby)
                self.assertEqual(sub_payload["PayloadIdentifier"], "com.zentral.mdm.fv.options")
            elif sub_payload_type == "com.apple.security.pkcs1":
                self.assertEqual(sub_payload["PayloadIdentifier"], "com.zentral.mdm.fv.certificate")
                escrow_cert_payload_uuid = sub_payload["PayloadUUID"]
            elif sub_payload_type == "com.apple.security.FDERecoveryKeyEscrow":
                self.assertEqual(sub_payload["EncryptCertPayloadUUID"], escrow_cert_payload_uuid)
                self.assertEqual(sub_payload["Location"], filevault_config.escrow_location_display_name)
                self.assertEqual(sub_payload["PayloadIdentifier"], "com.zentral.mdm.fv.escrow")
            else:
                continue
            found_sub_payloads += 1
        self.assertEqual(found_sub_payloads, 4)

    # process_response

    def test_process_acknowledged_response(self):
        self.enrolled_device.user_approved_enrollment = True
        self.enrolled_device.user_enrollment = False
        self.assertFalse(self.enrolled_device.awaiting_configuration)
        filevault_config = force_filevault_config()
        self.enrolled_device.blueprint = force_blueprint(filevault_config=filevault_config)
        cmd = SetupFileVault.create_for_target(Target(self.enrolled_device))
        cmd.process_response(
            {"UDID": self.enrolled_device.udid,
             "Status": "Acknowledged",
             "CommandUUID": str(cmd.uuid).upper()},
            self.dep_enrollment_session,
            self.mbu
        )
        cmd.db_command.refresh_from_db()
        self.assertEqual(cmd.status, Command.Status.ACKNOWLEDGED)
        self.assertEqual(cmd.db_command.status, Command.Status.ACKNOWLEDGED)
        self.enrolled_device.refresh_from_db()
        self.assertEqual(self.enrolled_device.filevault_config_uuid, filevault_config.uuid)
        # check next queued command is a SecurityInfo command to fetch the PRK
        qs = DeviceCommand.objects.filter(
            enrolled_device=self.enrolled_device,
            time__isnull=True
        )
        self.assertEqual(qs.count(), 1)
        db_cmd = qs.first()
        cmd = load_command(db_cmd)
        self.assertIsInstance(cmd, SecurityInfo)

    # _setup_filevault

    def test_setup_filevault_notnow_noop(self):
        self.enrolled_device.user_approved_enrollment = True
        self.enrolled_device.user_enrollment = False
        self.assertFalse(self.enrolled_device.awaiting_configuration)
        filevault_config = force_filevault_config()
        self.enrolled_device.blueprint = force_blueprint(filevault_config=filevault_config)
        self.assertIsNone(_setup_filevault(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.NOT_NOW,
        ))

    def test_setup_filevault_target_not_ok_noop(self):
        target = Target(self.enrolled_device)
        self.assertFalse(SetupFileVault.verify_target(target))
        self.assertIsNone(_setup_filevault(
            target,
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_setup_filevault_no_change_noop(self):
        self.enrolled_device.user_approved_enrollment = True
        self.enrolled_device.user_enrollment = False
        self.assertFalse(self.enrolled_device.awaiting_configuration)
        filevault_config = force_filevault_config()
        self.enrolled_device.blueprint = force_blueprint(filevault_config=filevault_config)
        self.enrolled_device.filevault_config_uuid = filevault_config.uuid
        self.assertIsNone(_setup_filevault(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_setup_filevault_recent_failed_command_noop(self):
        self.enrolled_device.user_approved_enrollment = True
        self.enrolled_device.user_enrollment = False
        self.assertFalse(self.enrolled_device.awaiting_configuration)
        filevault_config = force_filevault_config()
        self.enrolled_device.blueprint = force_blueprint(filevault_config=filevault_config)
        cmd = SetupFileVault.create_for_target(Target(self.enrolled_device))
        cmd.process_response(
            {"UDID": self.enrolled_device.udid,
             "Status": "Error",
             "CommandUUID": str(cmd.uuid).upper()},
            self.dep_enrollment_session,
            self.mbu
        )
        self.assertIsNone(_setup_filevault(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_setup_filevault_old_failed_command_ok(self):
        self.enrolled_device.user_approved_enrollment = True
        self.enrolled_device.user_enrollment = False
        self.assertFalse(self.enrolled_device.awaiting_configuration)
        filevault_config = force_filevault_config()
        self.enrolled_device.blueprint = force_blueprint(filevault_config=filevault_config)
        cmd = SetupFileVault.create_for_target(Target(self.enrolled_device))
        cmd.db_command.time = datetime.utcnow() - timedelta(hours=5)
        cmd.db_command.save()
        cmd.process_response(
            {"UDID": self.enrolled_device.udid,
             "Status": "Error",
             "CommandUUID": str(cmd.uuid).upper()},
            self.dep_enrollment_session,
            self.mbu
        )
        cmd = _setup_filevault(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(cmd, SetupFileVault)

    def test_setup_filevault_first_time_ok(self):
        self.enrolled_device.user_approved_enrollment = True
        self.enrolled_device.user_enrollment = False
        self.assertFalse(self.enrolled_device.awaiting_configuration)
        filevault_config = force_filevault_config()
        self.enrolled_device.blueprint = force_blueprint(filevault_config=filevault_config)
        cmd = _setup_filevault(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(cmd, SetupFileVault)

    def test_setup_filevault_change_ok(self):
        self.enrolled_device.user_approved_enrollment = True
        self.enrolled_device.user_enrollment = False
        self.assertFalse(self.enrolled_device.awaiting_configuration)
        filevault_config = force_filevault_config()
        self.enrolled_device.blueprint = force_blueprint(filevault_config=filevault_config)
        cmd = SetupFileVault.create_for_target(Target(self.enrolled_device))
        cmd.process_response(
            {"UDID": self.enrolled_device.udid,
             "Status": "Acknowledged",
             "CommandUUID": str(cmd.uuid).upper()},
            self.dep_enrollment_session,
            self.mbu
        )
        filevault_config.show_recovery_key = True
        cmd = _setup_filevault(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(cmd, SetupFileVault)

    def test_setup_filevault_reschedule_not_now(self):
        self.enrolled_device.user_approved_enrollment = True
        self.enrolled_device.user_enrollment = False
        self.assertFalse(self.enrolled_device.awaiting_configuration)
        filevault_config = force_filevault_config()
        self.enrolled_device.blueprint = force_blueprint(filevault_config=filevault_config)
        target = Target(self.enrolled_device)
        cmd = SetupFileVault.create_for_target(target)
        cmd.process_response(
            {"UDID": self.enrolled_device.udid,
             "Status": "NotNow",
             "CommandUUID": str(cmd.uuid).upper()},
            self.dep_enrollment_session,
            self.mbu
        )
        cmd2 = _get_next_queued_command(
            target,
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertEqual(cmd2, cmd)

import copy
from datetime import datetime
import os.path
import plistlib
from unittest.mock import patch
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.commands import SecurityInfo
from zentral.contrib.mdm.commands.scheduling import _update_base_inventory
from zentral.contrib.mdm.commands.setup_filevault import get_escrow_key_certificate_der_bytes
from zentral.contrib.mdm.crypto import encrypt_cms_payload
from zentral.contrib.mdm.events import (FileVaultPRKUpdatedEvent,
                                        RecoveryPasswordClearedEvent,
                                        RecoveryPasswordSetEvent,
                                        RecoveryPasswordUpdatedEvent)
from zentral.contrib.mdm.models import Blueprint, Channel, Platform, RequestStatus
from .utils import force_dep_enrollment_session


class SecurityInfoCommandTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.dep_enrollment_session, _, _ = force_dep_enrollment_session(
            cls.mbu,
            authenticated=True,
            completed=True,
            realm_user=True
        )
        cls.enrolled_device = cls.dep_enrollment_session.enrolled_device
        with open(os.path.join(os.path.dirname(__file__), "testdata/security_info.plist"), "rb") as f:
            cls.security_info = plistlib.load(f)
        with open(os.path.join(os.path.dirname(__file__), "testdata/security_info_ios.plist"), "rb") as f:
            cls.security_info_ios = plistlib.load(f)
        cls.blueprint = Blueprint.objects.create(name=get_random_string(12))
        cls.enrolled_device.blueprint = cls.blueprint
        cls.enrolled_device.save()

    # verify_channel_and_device

    def test_scope(self):
        for channel, platform, user_enrollment, result in (
            (Channel.DEVICE, Platform.IOS, False, True),
            (Channel.DEVICE, Platform.IPADOS, False, True),
            (Channel.DEVICE, Platform.MACOS, False, True),
            (Channel.DEVICE, Platform.TVOS, False, True),
            (Channel.USER, Platform.IOS, False, False),
            (Channel.USER, Platform.IPADOS, False, False),
            (Channel.USER, Platform.MACOS, False, False),
            (Channel.USER, Platform.TVOS, False, False),
            (Channel.DEVICE, Platform.IOS, True, True),
            (Channel.DEVICE, Platform.IPADOS, True, True),
            (Channel.DEVICE, Platform.MACOS, True, True),
            (Channel.DEVICE, Platform.TVOS, True, False),
        ):
            self.enrolled_device.platform = platform
            self.enrolled_device.user_enrollment = user_enrollment
            self.assertEqual(
                result,
                SecurityInfo.verify_channel_and_device(
                    channel, self.enrolled_device
                )
            )

    # build_command

    def test_build_command(self):
        cmd = SecurityInfo.create_for_device(
            self.dep_enrollment_session.enrolled_device
        )
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(payload["RequestType"], "SecurityInfo")

    # process_response

    def test_empty_response(self):
        self.assertIsNone(self.enrolled_device.security_info)
        self.assertIsNone(self.enrolled_device.security_info_updated_at)
        cmd = SecurityInfo.create_for_device(self.enrolled_device)
        cmd.process_response({"Status": "Acknowledged"}, self.dep_enrollment_session, self.mbu)
        self.enrolled_device.refresh_from_db()
        self.assertIsNone(self.enrolled_device.security_info)
        self.assertIsNone(self.enrolled_device.security_info_updated_at)

    def test_process_acknowledged_response(self):
        start = datetime.utcnow()
        self.assertIsNone(self.enrolled_device.security_info)
        self.assertIsNone(self.enrolled_device.security_info_updated_at)
        cmd = SecurityInfo.create_for_device(self.enrolled_device)
        cmd.process_response(self.security_info, self.dep_enrollment_session, self.mbu)
        self.enrolled_device.refresh_from_db()
        self.assertTrue(self.enrolled_device.security_info_updated_at > start)
        self.assertTrue(self.enrolled_device.security_info["FDE_Enabled"])
        self.assertTrue(self.enrolled_device.security_info_updated_at > start)
        self.assertFalse(self.enrolled_device.dep_enrollment)
        self.assertTrue(self.enrolled_device.activation_lock_manageable)
        self.assertFalse(self.enrolled_device.user_enrollment)
        self.assertTrue(self.enrolled_device.user_approved_enrollment)
        self.assertFalse(self.enrolled_device.bootstrap_token_allowed_for_authentication)
        self.assertTrue(self.enrolled_device.bootstrap_token_required_for_software_update)
        self.assertTrue(self.enrolled_device.bootstrap_token_required_for_kext_approval)

    def test_process_acknowledged_response_btafa_allowed(self):
        start = datetime.utcnow()
        self.assertIsNone(self.enrolled_device.security_info)
        self.assertIsNone(self.enrolled_device.security_info_updated_at)
        cmd = SecurityInfo.create_for_device(self.enrolled_device)
        security_info = copy.deepcopy(self.security_info)
        security_info["SecurityInfo"]["BootstrapTokenAllowedForAuthentication"] = "allowed"
        cmd.process_response(security_info, self.dep_enrollment_session, self.mbu)
        self.enrolled_device.refresh_from_db()
        self.assertTrue(self.enrolled_device.security_info_updated_at > start)
        self.assertTrue(self.enrolled_device.bootstrap_token_allowed_for_authentication)

    def test_process_acknowledged_response_btafa_not_supported(self):
        start = datetime.utcnow()
        self.assertIsNone(self.enrolled_device.security_info)
        self.assertIsNone(self.enrolled_device.security_info_updated_at)
        cmd = SecurityInfo.create_for_device(self.enrolled_device)
        security_info = copy.deepcopy(self.security_info)
        security_info["SecurityInfo"]["BootstrapTokenAllowedForAuthentication"] = "not supported"
        cmd.process_response(security_info, self.dep_enrollment_session, self.mbu)
        self.enrolled_device.refresh_from_db()
        self.assertTrue(self.enrolled_device.security_info_updated_at > start)
        self.assertIsNone(self.enrolled_device.bootstrap_token_allowed_for_authentication)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_process_acknowledged_response_update_filevault_prk(self, post_event):
        self.assertIsNone(self.enrolled_device.filevault_prk)
        cert = load_der_x509_certificate(get_escrow_key_certificate_der_bytes(self.enrolled_device))
        cert_bytes = cert.public_bytes(encoding=Encoding.PEM)
        cmd = SecurityInfo.create_for_device(self.enrolled_device)
        security_info = copy.deepcopy(self.security_info)
        security_info["SecurityInfo"]["FDE_PersonalRecoveryKeyCMS"] = encrypt_cms_payload(
            b"BBBB-BBBB-BBBB-BBBB-BBBB-BBBB",
            cert_bytes,
            raw_output=True
        )
        with self.captureOnCommitCallbacks(execute=True):
            cmd.process_response(security_info, self.dep_enrollment_session, self.mbu)
        self.enrolled_device.refresh_from_db()
        self.assertEqual(self.enrolled_device.get_filevault_prk(), "BBBB-BBBB-BBBB-BBBB-BBBB-BBBB")
        # event
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, FileVaultPRKUpdatedEvent)
        self.assertEqual(
            event.payload,
            {'command': {'request_type': 'SecurityInfo',
             'uuid': str(cmd.uuid)}}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["machine_serial_number"], self.enrolled_device.serial_number)
        self.assertEqual(metadata["objects"], {"mdm_command": [str(cmd.uuid)]})
        self.assertEqual(metadata["tags"], ["mdm"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_process_acknowledged_response_update_filevault_prk_bad_cms_payload_noop(self, post_event):
        self.enrolled_device.set_filevault_prk("BBBB-BBBB-BBBB-BBBB-BBBB-BBBB")
        self.enrolled_device.save()
        cmd = SecurityInfo.create_for_device(self.enrolled_device)
        security_info = copy.deepcopy(self.security_info)
        security_info["SecurityInfo"]["FDE_PersonalRecoveryKeyCMS"] = b"not-a-cms-payload"
        with self.captureOnCommitCallbacks(execute=True):
            cmd.process_response(security_info, self.dep_enrollment_session, self.mbu)
        self.enrolled_device.refresh_from_db()
        self.assertEqual(self.enrolled_device.get_filevault_prk(), "BBBB-BBBB-BBBB-BBBB-BBBB-BBBB")
        # no events
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_process_acknowledged_response_same_filevault_prk(self, post_event):
        self.enrolled_device.set_filevault_prk("BBBB-BBBB-BBBB-BBBB-BBBB-BBBB")
        self.enrolled_device.save()
        cert = load_der_x509_certificate(get_escrow_key_certificate_der_bytes(self.enrolled_device))
        cert_bytes = cert.public_bytes(encoding=Encoding.PEM)
        cmd = SecurityInfo.create_for_device(self.enrolled_device)
        security_info = copy.deepcopy(self.security_info)
        security_info["SecurityInfo"]["FDE_PersonalRecoveryKeyCMS"] = encrypt_cms_payload(
            b"BBBB-BBBB-BBBB-BBBB-BBBB-BBBB",
            cert_bytes,
            raw_output=True
        )
        with self.captureOnCommitCallbacks(execute=True):
            cmd.process_response(security_info, self.dep_enrollment_session, self.mbu)
        self.enrolled_device.refresh_from_db()
        self.assertEqual(self.enrolled_device.get_filevault_prk(), "BBBB-BBBB-BBBB-BBBB-BBBB-BBBB")
        # no events
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_process_acknowledged_response_pending_firmware_password_pending(self, post_event):
        self.assertIsNone(self.enrolled_device.recovery_password)
        self.enrolled_device.set_pending_firmware_password("12345678")
        self.enrolled_device.save()
        new_db_cmd_qs = self.enrolled_device.commands.filter(name="RestartDevice")
        self.assertEqual(new_db_cmd_qs.count(), 0)
        cmd = SecurityInfo.create_for_device(self.enrolled_device)
        security_info = copy.deepcopy(self.security_info)
        security_info["SecurityInfo"]["FirmwarePasswordStatus"] = {
            "PasswordExists": False,
            "AllowOroms": True,
            "ChangePending": True
        }
        with self.captureOnCommitCallbacks(execute=True):
            cmd.process_response(security_info, self.dep_enrollment_session, self.mbu)
        self.enrolled_device.refresh_from_db()
        self.assertEqual(self.enrolled_device.get_pending_firmware_password(), "12345678")
        self.assertIsNone(self.enrolled_device.recovery_password)
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 0)
        self.assertEqual(new_db_cmd_qs.count(), 1)
        new_db_cmd = new_db_cmd_qs.first()
        self.assertEqual(new_db_cmd.kwargs, {"NotifyUser": True})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_process_acknowledged_response_pending_firmware_password_set(self, post_event):
        self.assertIsNone(self.enrolled_device.recovery_password)
        self.enrolled_device.set_pending_firmware_password("12345678")
        self.enrolled_device.save()
        cmd = SecurityInfo.create_for_device(self.enrolled_device)
        security_info = copy.deepcopy(self.security_info)
        security_info["SecurityInfo"]["FirmwarePasswordStatus"] = {
            "PasswordExists": True,
            "AllowOroms": True,
            "Mode": "command",
            "ChangePending": False,
        }
        with self.captureOnCommitCallbacks(execute=True):
            cmd.process_response(security_info, self.dep_enrollment_session, self.mbu)
        self.enrolled_device.refresh_from_db()
        self.assertIsNone(self.enrolled_device.get_pending_firmware_password())
        self.assertIsNone(self.enrolled_device.pending_firmware_password_created_at)
        self.assertEqual(self.enrolled_device.get_recovery_password(), "12345678")
        self.assertEqual(self.enrolled_device.commands.filter(name="RestartDevice").count(), 0)
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, RecoveryPasswordSetEvent)
        self.assertEqual(
            event.payload,
            {'command': {'request_type': 'SecurityInfo',
                         'uuid': str(cmd.uuid)},
             'password_type': 'firmware_password'}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["machine_serial_number"], self.enrolled_device.serial_number)
        self.assertEqual(metadata["objects"], {"mdm_command": [str(cmd.uuid)]})
        self.assertEqual(set(metadata["tags"]), {"mdm", "recovery_password"})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_process_acknowledged_response_pending_firmware_password_update(self, post_event):
        self.assertIsNone(self.enrolled_device.recovery_password)
        self.enrolled_device.set_recovery_password("87654321")
        self.enrolled_device.set_pending_firmware_password("12345678")
        self.enrolled_device.save()
        cmd = SecurityInfo.create_for_device(self.enrolled_device)
        security_info = copy.deepcopy(self.security_info)
        security_info["SecurityInfo"]["FirmwarePasswordStatus"] = {
            "PasswordExists": True,
            "AllowOroms": True,
            "Mode": "command",
            "ChangePending": False,
        }
        with self.captureOnCommitCallbacks(execute=True):
            cmd.process_response(security_info, self.dep_enrollment_session, self.mbu)
        self.enrolled_device.refresh_from_db()
        self.assertIsNone(self.enrolled_device.get_pending_firmware_password())
        self.assertIsNone(self.enrolled_device.pending_firmware_password_created_at)
        self.assertEqual(self.enrolled_device.get_recovery_password(), "12345678")
        self.assertEqual(self.enrolled_device.commands.filter(name="RestartDevice").count(), 0)
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, RecoveryPasswordUpdatedEvent)
        self.assertEqual(
            event.payload,
            {'command': {'request_type': 'SecurityInfo',
                         'uuid': str(cmd.uuid)},
             'password_type': 'firmware_password'}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["machine_serial_number"], self.enrolled_device.serial_number)
        self.assertEqual(metadata["objects"], {"mdm_command": [str(cmd.uuid)]})
        self.assertEqual(set(metadata["tags"]), {"mdm", "recovery_password"})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_process_acknowledged_response_pending_firmware_password_clear(self, post_event):
        self.assertIsNone(self.enrolled_device.recovery_password)
        self.enrolled_device.set_recovery_password("87654321")
        self.enrolled_device.set_pending_firmware_password("")
        self.enrolled_device.save()
        cmd = SecurityInfo.create_for_device(self.enrolled_device)
        security_info = copy.deepcopy(self.security_info)
        security_info["SecurityInfo"]["FirmwarePasswordStatus"] = {
            "PasswordExists": False,
            "AllowOroms": True,
            "Mode": "command",
            "ChangePending": False,
        }
        with self.captureOnCommitCallbacks(execute=True):
            cmd.process_response(security_info, self.dep_enrollment_session, self.mbu)
        self.enrolled_device.refresh_from_db()
        self.assertIsNone(self.enrolled_device.get_pending_firmware_password())
        self.assertIsNone(self.enrolled_device.pending_firmware_password_created_at)
        self.assertIsNone(self.enrolled_device.get_recovery_password())
        self.assertEqual(self.enrolled_device.commands.filter(name="RestartDevice").count(), 0)
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, RecoveryPasswordClearedEvent)
        self.assertEqual(
            event.payload,
            {'command': {'request_type': 'SecurityInfo',
                         'uuid': str(cmd.uuid)},
             'password_type': 'firmware_password'}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["machine_serial_number"], self.enrolled_device.serial_number)
        self.assertEqual(metadata["objects"], {"mdm_command": [str(cmd.uuid)]})
        self.assertEqual(set(metadata["tags"]), {"mdm", "recovery_password"})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_process_acknowledged_response_pending_firmware_password_clear_error(self, post_event):
        self.assertIsNone(self.enrolled_device.recovery_password)
        self.enrolled_device.set_recovery_password("87654321")
        self.enrolled_device.set_pending_firmware_password("")
        self.enrolled_device.save()
        cmd = SecurityInfo.create_for_device(self.enrolled_device)
        security_info = copy.deepcopy(self.security_info)
        security_info["SecurityInfo"]["FirmwarePasswordStatus"] = {
            "PasswordExists": True,  # the problem
            "AllowOroms": True,
            "Mode": "command",
            "ChangePending": False,
        }
        with self.captureOnCommitCallbacks(execute=True):
            cmd.process_response(security_info, self.dep_enrollment_session, self.mbu)
        self.enrolled_device.refresh_from_db()
        self.assertEqual(self.enrolled_device.get_recovery_password(), "87654321")
        self.assertIsNone(self.enrolled_device.pending_firmware_password)
        self.assertIsNone(self.enrolled_device.pending_firmware_password_created_at)
        # no events
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_process_acknowledged_response_no_firmware_password_anymore(self, post_event):
        self.enrolled_device.set_recovery_password("123")
        self.enrolled_device.save()
        cmd = SecurityInfo.create_for_device(self.enrolled_device)
        security_info = copy.deepcopy(self.security_info)
        security_info["SecurityInfo"]["FirmwarePasswordStatus"] = {
            "PasswordExists": False,  # the problem
        }
        with self.captureOnCommitCallbacks(execute=True):
            cmd.process_response(security_info, self.dep_enrollment_session, self.mbu)
        self.enrolled_device.refresh_from_db()
        self.assertIsNone(self.enrolled_device.recovery_password)
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, RecoveryPasswordClearedEvent)
        self.assertEqual(
            event.payload,
            {'command': {'request_type': 'SecurityInfo',
                         'uuid': str(cmd.uuid)},
             'password_type': 'firmware_password'}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["machine_serial_number"], self.enrolled_device.serial_number)
        self.assertEqual(metadata["objects"], {"mdm_command": [str(cmd.uuid)]})
        self.assertEqual(set(metadata["tags"]), {"mdm", "recovery_password"})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_process_acknowledged_response_firmware_password_still_there(self, post_event):
        self.enrolled_device.set_recovery_password("123")
        self.enrolled_device.save()
        cmd = SecurityInfo.create_for_device(self.enrolled_device)
        security_info = copy.deepcopy(self.security_info)
        security_info["SecurityInfo"]["FirmwarePasswordStatus"] = {
            "PasswordExists": True,  # OK
        }
        with self.captureOnCommitCallbacks(execute=True):
            cmd.process_response(security_info, self.dep_enrollment_session, self.mbu)
        self.enrolled_device.refresh_from_db()
        self.assertEqual(self.enrolled_device.get_recovery_password(), "123")
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_process_acknowledged_response_no_recovery_lock_anymore(self, post_event):
        self.enrolled_device.set_recovery_password("123")
        self.enrolled_device.save()
        cmd = SecurityInfo.create_for_device(self.enrolled_device)
        security_info = copy.deepcopy(self.security_info)
        security_info["SecurityInfo"]["IsRecoveryLockEnabled"] = False  # the problem
        security_info["SecurityInfo"].pop("FirmwarePasswordStatus", None)
        with self.captureOnCommitCallbacks(execute=True):
            cmd.process_response(security_info, self.dep_enrollment_session, self.mbu)
        self.enrolled_device.refresh_from_db()
        self.assertIsNone(self.enrolled_device.recovery_password)
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, RecoveryPasswordClearedEvent)
        self.assertEqual(
            event.payload,
            {'command': {'request_type': 'SecurityInfo',
                         'uuid': str(cmd.uuid)},
             'password_type': 'recovery_lock'}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["machine_serial_number"], self.enrolled_device.serial_number)
        self.assertEqual(metadata["objects"], {"mdm_command": [str(cmd.uuid)]})
        self.assertEqual(set(metadata["tags"]), {"mdm", "recovery_password"})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_process_acknowledged_response_recovery_lock_still_there(self, post_event):
        self.enrolled_device.set_recovery_password("123")
        self.enrolled_device.save()
        cmd = SecurityInfo.create_for_device(self.enrolled_device)
        security_info = copy.deepcopy(self.security_info)
        security_info["SecurityInfo"]["IsRecoveryLockEnabled"] = True  # OK
        security_info["SecurityInfo"].pop("FirmwarePasswordStatus", None)
        with self.captureOnCommitCallbacks(execute=True):
            cmd.process_response(security_info, self.dep_enrollment_session, self.mbu)
        self.enrolled_device.refresh_from_db()
        self.assertEqual(self.enrolled_device.get_recovery_password(), "123")
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 0)

    def test_process_acknowledged_ios_response(self):
        start = datetime.utcnow()
        self.assertIsNone(self.enrolled_device.security_info)
        self.assertIsNone(self.enrolled_device.security_info_updated_at)
        self.enrolled_device.dep_enrollment = True
        self.enrolled_device.user_enrollment = False
        self.enrolled_device.user_approved_enrollment = True
        self.enrolled_device.save()
        cmd = SecurityInfo.create_for_device(self.enrolled_device)
        cmd.process_response(self.security_info_ios, self.dep_enrollment_session, self.mbu)
        self.enrolled_device.refresh_from_db()
        self.assertTrue(self.enrolled_device.security_info_updated_at > start)
        self.assertTrue(self.enrolled_device.dep_enrollment)
        self.assertIsNone(self.enrolled_device.activation_lock_manageable)
        self.assertFalse(self.enrolled_device.user_enrollment)
        self.assertTrue(self.enrolled_device.user_approved_enrollment)
        self.assertIsNone(self.enrolled_device.bootstrap_token_allowed_for_authentication)
        self.assertIsNone(self.enrolled_device.bootstrap_token_required_for_software_update)
        self.assertIsNone(self.enrolled_device.bootstrap_token_required_for_kext_approval)

    # _update_base_inventory

    def test_update_base_inventory_security_info_updated_at_old(self):
        self.enrolled_device.device_information_updated_at = datetime.utcnow()
        self.enrolled_device.security_info_updated_at = datetime(2000, 1, 1)
        cmd = _update_base_inventory(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(cmd, SecurityInfo)

    def test_update_base_inventory_security_info_updated_at_ok_no_inventory_items_collection_noop(self):
        self.enrolled_device.device_information_updated_at = datetime.utcnow()
        self.enrolled_device.security_info_updated_at = datetime.utcnow()
        self.assertEqual(self.blueprint.collect_apps, Blueprint.InventoryItemCollectionOption.NO)
        self.assertEqual(self.blueprint.collect_certificates, Blueprint.InventoryItemCollectionOption.NO)
        self.assertEqual(self.blueprint.collect_profiles, Blueprint.InventoryItemCollectionOption.NO)
        self.assertIsNone(
            _update_base_inventory(
                Target(self.enrolled_device),
                self.dep_enrollment_session,
                RequestStatus.IDLE,
            )
        )

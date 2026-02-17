import uuid
from datetime import datetime

from django.test import TestCase
from django.utils.crypto import get_random_string

from zentral.contrib.mdm.models import EnrolledDevice

from .utils import force_push_certificate


class TestMDMModels(TestCase):
    def test_enrolled_device_set_bootstrap_token_none(self):
        enrolled_device = EnrolledDevice.objects.create(
            udid=uuid.uuid4(),
            serial_number=get_random_string(12),
            push_certificate=force_push_certificate(),
        )
        enrolled_device.set_bootstrap_token(None)
        self.assertIsNone(enrolled_device.bootstrap_token)
        self.assertIsNone(enrolled_device.get_bootstrap_token())

    def test_enrolled_device_set_unlock_token_none(self):
        enrolled_device = EnrolledDevice.objects.create(
            udid=uuid.uuid4(),
            serial_number=get_random_string(12),
            push_certificate=force_push_certificate(),
        )
        enrolled_device.set_unlock_token(None)
        self.assertIsNone(enrolled_device.unlock_token)
        self.assertIsNone(enrolled_device.get_unlock_token())

    def test_enrolled_device_set_filevault_escrow_key_none(self):
        enrolled_device = EnrolledDevice.objects.create(
            udid=uuid.uuid4(),
            serial_number=get_random_string(12),
            push_certificate=force_push_certificate(),
        )
        enrolled_device.set_filevault_escrow_key(None)
        self.assertIsNone(enrolled_device.filevault_escrow_key)
        self.assertIsNone(enrolled_device.get_filevault_escrow_key())

    def test_enrolled_device_set_filevault_prk_none(self):
        enrolled_device = EnrolledDevice.objects.create(
            udid=uuid.uuid4(),
            serial_number=get_random_string(12),
            push_certificate=force_push_certificate(),
        )
        enrolled_device.set_filevault_prk(None)
        self.assertIsNone(enrolled_device.filevault_prk)
        self.assertIsNone(enrolled_device.get_filevault_prk())

    def test_enrolled_device_set_recovery_password_none(self):
        enrolled_device = EnrolledDevice.objects.create(
            udid=uuid.uuid4(),
            serial_number=get_random_string(12),
            push_certificate=force_push_certificate(),
        )
        enrolled_device.set_recovery_password(None)
        self.assertIsNone(enrolled_device.recovery_password)
        self.assertIsNone(enrolled_device.get_recovery_password())

    def test_enrolled_device_set_pending_firmware_password_none(self):
        enrolled_device = EnrolledDevice.objects.create(
            udid=uuid.uuid4(),
            serial_number=get_random_string(12),
            push_certificate=force_push_certificate(),
        )
        enrolled_device.set_pending_firmware_password(None)
        self.assertIsNone(enrolled_device.recovery_password)
        self.assertIsNone(enrolled_device.pending_firmware_password_created_at)
        self.assertIsNone(enrolled_device.get_pending_firmware_password())

    def test_enrolled_device_rewrap_secrets(self):
        enrolled_device = EnrolledDevice.objects.create(
            udid=uuid.uuid4(),
            serial_number=get_random_string(12),
            push_certificate=force_push_certificate(),
        )
        bootstrap_token = get_random_string(12).encode("utf-8")
        enrolled_device.set_bootstrap_token(bootstrap_token)
        unlock_token = get_random_string(12).encode("utf-8")
        enrolled_device.set_unlock_token(unlock_token)
        filevault_escrow_key = get_random_string(12).encode("utf-8")
        enrolled_device.set_filevault_escrow_key(filevault_escrow_key)
        filevault_prk = get_random_string(12)
        enrolled_device.set_filevault_prk(filevault_prk)
        recovery_password = get_random_string(12)
        enrolled_device.set_recovery_password(recovery_password)
        pending_firmware_password = get_random_string(12)
        enrolled_device.set_pending_firmware_password(pending_firmware_password)
        admin_password = get_random_string(12)
        enrolled_device.set_admin_password(admin_password)
        device_lock_pin = get_random_string(6, "0123456789")
        enrolled_device.set_device_lock_pin(device_lock_pin)
        enrolled_device.rewrap_secrets()
        self.assertEqual(enrolled_device.get_bootstrap_token(), bootstrap_token)
        self.assertEqual(enrolled_device.get_unlock_token(), unlock_token)
        self.assertEqual(enrolled_device.get_filevault_escrow_key(), filevault_escrow_key)
        self.assertEqual(enrolled_device.get_filevault_prk(), filevault_prk)
        self.assertEqual(enrolled_device.get_recovery_password(), recovery_password)
        self.assertEqual(enrolled_device.get_pending_firmware_password(), pending_firmware_password)
        self.assertEqual(enrolled_device.get_admin_password(), admin_password)
        self.assertEqual(enrolled_device.get_device_lock_pin(), device_lock_pin)

    # urlsafe serial number

    def test_enrolled_device_get_urlsafe_serial_number(self):
        enrolled_device = EnrolledDevice.objects.create(
            udid=uuid.uuid4(),
            serial_number="0123456789",
            push_certificate=force_push_certificate(),
        )
        self.assertEqual("0123456789", enrolled_device.get_urlsafe_serial_number())

    # current enrollment / enrollment session

    def test_enrolled_device_blocked_no_current_enrollment_session(self):
        enrolled_device = EnrolledDevice.objects.create(
            udid=uuid.uuid4(),
            serial_number="0123456789",
            push_certificate=force_push_certificate(),
            blocked_at=datetime.utcnow(),
        )
        self.assertIsNone(enrolled_device.current_enrollment_session)
        self.assertIsNone(enrolled_device.current_enrollment)

    def test_enrolled_device_no_current_enrollment_session(self):
        enrolled_device = EnrolledDevice.objects.create(
            udid=uuid.uuid4(),
            serial_number="0123456789",
            push_certificate=force_push_certificate(),
        )
        self.assertIsNone(enrolled_device.current_enrollment_session)
        self.assertIsNone(enrolled_device.current_enrollment)

    # auto admin

    def test_enrolled_device_auto_admin_info(self):
        enrolled_device = EnrolledDevice.objects.create(
            udid=uuid.uuid4(),
            serial_number="0123456789",
            push_certificate=force_push_certificate(),
            device_information={
                "AutoSetupAdminAccounts": [
                    {"GUID": "yolo", "shortName": "fomo"}
                ]
            }
        )
        self.assertEqual(enrolled_device.admin_guid, "yolo")
        self.assertEqual(enrolled_device.admin_shortname, "fomo")
        self.assertFalse(enrolled_device.admin_password_escrowed)
        enrolled_device.set_admin_password("pwd")
        self.assertTrue(enrolled_device.admin_password_escrowed)

    def test_enrolled_device_no_auto_admin_info(self):
        enrolled_device = EnrolledDevice.objects.create(
            udid=uuid.uuid4(),
            serial_number="0123456789",
            push_certificate=force_push_certificate(),
            device_information={
                "AutoSetupAdminAccounts": [
                    {"GUID": "yolo", "shortName": "fomo"},
                    {"GUID": "yolo2", "shortName": "fomo2"}  # Zentral only manages 1 auto admin
                ]
            }
        )
        self.assertIsNone(enrolled_device.admin_guid)
        self.assertIsNone(enrolled_device.admin_shortname)
        self.assertFalse(enrolled_device.admin_password_escrowed)

from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from io import StringIO
from unittest.mock import Mock
import uuid
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import load_der_x509_certificate
from django.core.management import call_command
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.commands import (AccountConfiguration, DeviceConfigured, DeviceLock, RotateFileVaultKey,
                                          SetAutoAdminPassword, SetFirmwarePassword, SetRecoveryLock, SetupFileVault)
from zentral.contrib.mdm.commands.base import get_secret_engine_kwargs, load_command
from zentral.contrib.mdm.commands.rotate_filevault_key import get_encryption_cert_der_bytes
from zentral.contrib.mdm.commands.setup_filevault import get_escrow_key
from zentral.contrib.mdm.crypto import encrypt_cms_payload
from zentral.contrib.mdm.models import DeviceCommand, EnrolledDevice
from zentral.core.secret_engines import encrypt_str, secret_engines

from .utils import force_dep_enrollment_session, force_filevault_config


SECRET_FIELDS = {
    "bootstrap_token", "unlock_token", "filevault_escrow_key", "filevault_prk",
    "recovery_password", "pending_firmware_password", "admin_password", "device_lock_pin",
}


class EnrolledDeviceRewrapSecretsTestCase(TestCase):
    # An enrolled device is loaded, its secrets are rewrapped in the DB, then the loaded device is saved.
    # The secrets that the save does not set must keep their rewrapped value.

    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.session, _, _ = force_dep_enrollment_session(cls.mbu, completed=True)
        cls.enrolled_device = cls.session.enrolled_device

    def setUp(self):
        super().setUp()
        secret_engines.load_config({})
        self.addCleanup(secret_engines.load_config, {})

    def _set_secrets(self, exclude=(), **attrs):
        enrolled_device = EnrolledDevice.objects.get(pk=self.enrolled_device.pk)
        enrolled_device.set_bootstrap_token(b"bootstrap")
        enrolled_device.set_unlock_token(b"unlock")
        enrolled_device.set_filevault_escrow_key(b"escrow")
        enrolled_device.set_filevault_prk("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
        enrolled_device.set_recovery_password("recovery")
        enrolled_device.set_pending_firmware_password("pending")
        enrolled_device.set_admin_password("admin")
        enrolled_device.set_device_lock_pin("123456")
        for field in exclude:
            setattr(enrolled_device, field, None)
        for attr, value in attrs.items():
            setattr(enrolled_device, attr, value)
        enrolled_device.save()

    def _rewrap_in_db(self):
        secret_engines.load_config({
            "fernet": {"backend": "zentral.core.secret_engines.backends.fernet",
                       "passwords": ["undeuxtrois"]}
        })
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            call_command("rewrap_secrets")

    def _assert_rewrapped(self, written_fields):
        enrolled_device = EnrolledDevice.objects.get(pk=self.enrolled_device.pk)
        for field in sorted(SECRET_FIELDS - set(written_fields)):
            with self.subTest(field):
                self.assertEqual(getattr(enrolled_device, field).split("$")[0], "fernet")
        return enrolled_device

    def _load_command(self, command_class, kwargs=None, secret=None):
        command_uuid = uuid.uuid4()
        kwargs = dict(kwargs or {})
        if secret:
            key, value = secret
            kwargs[key] = encrypt_str(value, **get_secret_engine_kwargs(command_uuid, key))
        db_command = DeviceCommand.objects.create(
            uuid=command_uuid, name=command_class.get_db_name(), kwargs=kwargs,
            enrolled_device=EnrolledDevice.objects.get(pk=self.enrolled_device.pk),
        )
        return load_command(DeviceCommand.objects.get(pk=db_command.pk))

    def _acknowledge(self, command, **response):
        command.process_response(
            {"UDID": self.enrolled_device.udid, "Status": "Acknowledged", "CommandUUID": str(command.uuid).upper(),
             **response},
            self.session, self.mbu
        )

    # commands

    def test_account_configuration_acknowledged(self):
        self._set_secrets()
        command = self._load_command(AccountConfiguration, secret=("admin_password", "new admin"))
        self._rewrap_in_db()
        self._acknowledge(command)
        enrolled_device = self._assert_rewrapped({"admin_password"})
        self.assertEqual(enrolled_device.get_admin_password(), "new admin")

    def test_device_configured_acknowledged(self):
        self._set_secrets(awaiting_configuration=True)
        command = self._load_command(DeviceConfigured)
        self._rewrap_in_db()
        self._acknowledge(command)
        enrolled_device = self._assert_rewrapped(())
        self.assertFalse(enrolled_device.awaiting_configuration)

    def test_device_lock_acknowledged(self):
        self._set_secrets()
        command = self._load_command(DeviceLock, secret=("PIN", "654321"))
        self._rewrap_in_db()
        self._acknowledge(command)
        enrolled_device = self._assert_rewrapped({"device_lock_pin"})
        self.assertEqual(enrolled_device.get_device_lock_pin(), "654321")

    def test_rotate_filevault_key_acknowledged(self):
        self._set_secrets()
        command = RotateFileVaultKey.create_for_target(
            Target(EnrolledDevice.objects.get(pk=self.enrolled_device.pk))
        )
        cert = load_der_x509_certificate(get_encryption_cert_der_bytes(command.load_encryption_key()))
        prk_cms = encrypt_cms_payload(b"BBBB-BBBB-BBBB-BBBB-BBBB-BBBB", cert.public_bytes(encoding=Encoding.PEM),
                                      raw_output=True)
        self._rewrap_in_db()
        self._acknowledge(command, RotateResult={"EncryptedNewRecoveryKey": prk_cms})
        enrolled_device = self._assert_rewrapped({"filevault_prk"})
        self.assertEqual(enrolled_device.get_filevault_prk(), "BBBB-BBBB-BBBB-BBBB-BBBB-BBBB")

    def test_set_auto_admin_password_acknowledged(self):
        self._set_secrets()
        command = self._load_command(SetAutoAdminPassword, secret=("new_password", "new admin"))
        self._rewrap_in_db()
        self._acknowledge(command)
        enrolled_device = self._assert_rewrapped({"admin_password"})
        self.assertEqual(enrolled_device.get_admin_password(), "new admin")

    def test_set_firmware_password_acknowledged(self):
        self._set_secrets()
        command = self._load_command(SetFirmwarePassword, secret=("new_password", "new firmware"))
        self._rewrap_in_db()
        self._acknowledge(command, SetFirmwarePassword={"PasswordChanged": True})
        enrolled_device = self._assert_rewrapped({"pending_firmware_password"})
        self.assertEqual(enrolled_device.get_pending_firmware_password(), "new firmware")

    def test_set_recovery_lock_acknowledged(self):
        self._set_secrets()
        command = self._load_command(SetRecoveryLock, secret=("new_password", "new recovery"))
        self._rewrap_in_db()
        self._acknowledge(command)
        enrolled_device = self._assert_rewrapped({"recovery_password"})
        self.assertEqual(enrolled_device.get_recovery_password(), "new recovery")

    def test_setup_filevault_acknowledged(self):
        self._set_secrets()
        filevault_config = force_filevault_config()
        command = self._load_command(SetupFileVault, kwargs={"filevault_config_pk": filevault_config.pk,
                                                             "filevault_config_uuid": str(filevault_config.uuid)})
        self._rewrap_in_db()
        self._acknowledge(command)
        enrolled_device = self._assert_rewrapped(())
        self.assertEqual(enrolled_device.filevault_config_uuid, filevault_config.uuid)

    def test_setup_filevault_escrow_key(self):
        self._set_secrets(exclude=("filevault_escrow_key",))
        enrolled_device = EnrolledDevice.objects.get(pk=self.enrolled_device.pk)
        self._rewrap_in_db()
        get_escrow_key(enrolled_device)
        enrolled_device = self._assert_rewrapped({"filevault_escrow_key"})
        self.assertIsNotNone(enrolled_device.get_filevault_escrow_key())

    # enrolled device methods

    def test_block(self):
        self._set_secrets()
        enrolled_device = EnrolledDevice.objects.get(pk=self.enrolled_device.pk)
        self._rewrap_in_db()
        enrolled_device.block()
        self.assertIsNotNone(self._assert_rewrapped(()).blocked_at)

    def test_unblock(self):
        self._set_secrets()
        enrolled_device = EnrolledDevice.objects.get(pk=self.enrolled_device.pk)
        enrolled_device.block()
        self._rewrap_in_db()
        enrolled_device.unblock()
        self.assertIsNone(self._assert_rewrapped(()).blocked_at)

    def test_purge_state(self):
        self._set_secrets()
        enrolled_device = EnrolledDevice.objects.get(pk=self.enrolled_device.pk)
        enrolled_device.block()
        self._rewrap_in_db()
        enrolled_device.purge_state(full=True)
        enrolled_device = self._assert_rewrapped({"filevault_escrow_key", "device_lock_pin"})
        self.assertIsNone(enrolled_device.filevault_escrow_key)
        self.assertIsNone(enrolled_device.device_lock_pin)
        self.assertIsNone(enrolled_device.blocked_at)

    def test_unlock_device_pin(self):
        self._set_secrets()
        EnrolledDevice.objects.filter(pk=self.enrolled_device.pk).update(updated_at=datetime(2000, 1, 1))
        enrolled_device = EnrolledDevice.objects.get(pk=self.enrolled_device.pk)
        self._rewrap_in_db()
        Target(enrolled_device).unlock_device_pin(Mock())
        enrolled_device = self._assert_rewrapped({"device_lock_pin"})
        self.assertIsNone(enrolled_device.device_lock_pin)
        self.assertGreater(enrolled_device.updated_at, datetime(2000, 1, 1))

    def test_do_checkout(self):
        self._set_secrets()
        enrolled_device = EnrolledDevice.objects.get(pk=self.enrolled_device.pk)
        self._rewrap_in_db()
        enrolled_device.do_checkout()
        enrolled_device = self._assert_rewrapped(
            {"bootstrap_token", "unlock_token", "filevault_escrow_key", "device_lock_pin"}
        )
        self.assertIsNone(enrolled_device.bootstrap_token)
        self.assertIsNone(enrolled_device.unlock_token)
        self.assertIsNone(enrolled_device.token)
        self.assertIsNotNone(enrolled_device.checkout_at)

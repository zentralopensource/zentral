from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import uuid
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.commands import (AccountConfiguration, DeviceInformation, DeviceLock, EraseDevice,
                                          RotateFileVaultKey, SetAutoAdminPassword, SetFirmwarePassword,
                                          SetRecoveryLock)
from zentral.contrib.mdm.commands.base import get_secret_engine_kwargs, load_command, registered_commands
from zentral.contrib.mdm.models import DeviceCommand, UserCommand
from zentral.core.secret_engines import decrypt, encrypt, secret_engines

from .utils import force_dep_enrollment_session, force_enrolled_user


SECRET_COMMANDS = {
    AccountConfiguration: "admin_password",
    DeviceLock: "PIN",
    EraseDevice: "PIN",
    RotateFileVaultKey: "encryption_key",
    SetAutoAdminPassword: "new_password",
    SetFirmwarePassword: "new_password",
    SetRecoveryLock: "new_password",
}


class CommandRewrapSecretsTestCase(TestCase):
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

    def _load_fernet_engine(self):
        secret_engines.load_config({
            "fernet": {"backend": "zentral.core.secret_engines.backends.fernet",
                       "passwords": ["undeuxtrois"]}
        })

    def _force_command(self, command_class, kwargs=None, secret=None, model=DeviceCommand, target=None):
        command_uuid = uuid.uuid4()
        kwargs = dict(kwargs or {})
        if secret is not None:
            key = SECRET_COMMANDS[command_class]
            kwargs[key] = encrypt(secret, **get_secret_engine_kwargs(command_uuid, key))
        if target is None:
            target = {"enrolled_device": self.enrolled_device}
        return model.objects.create(uuid=command_uuid, name=command_class.get_db_name(), kwargs=kwargs, **target)

    def _decrypt(self, db_command, key):
        return decrypt(db_command.kwargs[key], **get_secret_engine_kwargs(db_command.uuid, key))

    # the declarations

    def test_secret_commands(self):
        self.assertEqual(
            {command_class: command_class.secret_kwargs
             for command_class in registered_commands.values()
             if command_class.secret_kwargs},
            {command_class: (key,) for command_class, key in SECRET_COMMANDS.items()}
        )

    # rewrap_kwargs

    def test_rewrap_kwargs(self):
        self._load_fernet_engine()
        command_uuid = uuid.uuid4()
        encrypted_pin = encrypt(b"123456", **get_secret_engine_kwargs(command_uuid, "PIN"))
        kwargs = {"PIN": encrypted_pin, "Message": "lost"}
        rewrapped_kwargs = DeviceLock.rewrap_kwargs(command_uuid, kwargs)
        self.assertEqual(kwargs, {"PIN": encrypted_pin, "Message": "lost"})
        self.assertEqual(set(rewrapped_kwargs), {"PIN", "Message"})
        self.assertNotEqual(rewrapped_kwargs["PIN"], encrypted_pin)
        self.assertEqual(decrypt(rewrapped_kwargs["PIN"], **get_secret_engine_kwargs(command_uuid, "PIN")),
                         b"123456")
        self.assertEqual(rewrapped_kwargs["Message"], "lost")

    def test_rewrap_kwargs_empty_value(self):
        self.assertEqual(SetRecoveryLock.rewrap_kwargs(uuid.uuid4(), {"new_password": ""}), {"new_password": ""})

    # rewrap_secrets

    def test_rewrap_secrets(self):
        for command_class, key in SECRET_COMMANDS.items():
            with self.subTest(command_class.request_type):
                secret_engines.load_config({})
                secret = get_random_string(12).encode("utf-8")
                db_command = self._force_command(command_class, kwargs={"public": "yes"}, secret=secret)
                self.assertEqual(db_command.kwargs[key].split("$")[0], "noop")
                self._load_fernet_engine()
                db_command.rewrap_secrets()
                self.assertEqual(db_command.kwargs[key].split("$")[0], "fernet")
                self.assertEqual(self._decrypt(db_command, key), secret)
                self.assertEqual(db_command.kwargs["public"], "yes")

    def test_rewrap_secrets_loaded_by_the_command(self):
        db_command = self._force_command(DeviceLock, secret=b"123456")
        self._load_fernet_engine()
        db_command.rewrap_secrets()
        db_command.save()
        db_command.refresh_from_db()
        self.assertEqual(db_command.kwargs["PIN"].split("$")[0], "fernet")
        self.assertEqual(load_command(db_command).load_pin(), "123456")

    def test_rewrap_secrets_unknown_command(self):
        db_command = DeviceCommand.objects.create(
            uuid=uuid.uuid4(),
            name=get_random_string(12),
            kwargs={"PIN": "noop$MTIzNDU2"},
            enrolled_device=self.enrolled_device,
        )
        self._load_fernet_engine()
        db_command.rewrap_secrets()
        self.assertEqual(db_command.kwargs, {"PIN": "noop$MTIzNDU2"})

    # rewrap_secrets_queryset

    def test_device_command_rewrap_secrets_queryset(self):
        expected_commands = [self._force_command(command_class, secret=b"yolo") for command_class in SECRET_COMMANDS]
        self._force_command(EraseDevice, kwargs={"PreserveDataPlan": True})
        self._force_command(DeviceInformation)
        DeviceCommand.objects.create(uuid=uuid.uuid4(), name=get_random_string(12), kwargs={"PIN": "noop$MTIzNDU2"},
                                     enrolled_device=self.enrolled_device)
        self.assertEqual(
            sorted(DeviceCommand.rewrap_secrets_queryset().values_list("pk", flat=True)),
            sorted(db_command.pk for db_command in expected_commands)
        )

    def test_user_command_rewrap_secrets_queryset(self):
        enrolled_user = force_enrolled_user(self.enrolled_device)
        self._force_command(DeviceInformation, model=UserCommand, target={"enrolled_user": enrolled_user})
        self.assertEqual(UserCommand.rewrap_secrets_queryset().count(), 0)
        db_command = self._force_command(DeviceLock, secret=b"123456",
                                         model=UserCommand, target={"enrolled_user": enrolled_user})
        self.assertEqual(list(UserCommand.rewrap_secrets_queryset()), [db_command])

    # a command loaded before the rewrap

    def _rewrap_in_db(self, db_command):
        self._load_fernet_engine()
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            call_command("rewrap_secrets")
        rewrapped_kwargs = DeviceCommand.objects.get(pk=db_command.pk).kwargs
        self.assertEqual(rewrapped_kwargs["PIN"].split("$")[0], "fernet")
        return rewrapped_kwargs

    def test_process_response_keeps_the_rewrapped_kwargs(self):
        db_command = self._force_command(DeviceLock, secret=b"123456")
        db_command.time = db_command.created_at
        db_command.save()
        command = load_command(db_command)
        rewrapped_kwargs = self._rewrap_in_db(db_command)
        command.process_response({"Status": "Error", "ErrorChain": []}, self.session, self.mbu)
        db_command.refresh_from_db()
        self.assertEqual(db_command.status, "Error")
        self.assertEqual(db_command.kwargs, rewrapped_kwargs)

    def test_set_time_keeps_the_rewrapped_kwargs(self):
        db_command = self._force_command(DeviceLock, secret=b"123456")
        command = load_command(db_command)
        rewrapped_kwargs = self._rewrap_in_db(db_command)
        command.set_time()
        db_command.refresh_from_db()
        self.assertIsNotNone(db_command.time)
        self.assertEqual(db_command.kwargs, rewrapped_kwargs)

    # management command

    def test_rewrap_secrets_management_command_decryption_error(self):
        failing_db_command = DeviceCommand.objects.create(
            uuid=uuid.uuid4(),
            name=DeviceLock.get_db_name(),
            kwargs={"PIN": "yolo$fomo"},
            enrolled_device=self.enrolled_device,
        )
        db_command = self._force_command(DeviceLock, secret=b"123456")
        self._load_fernet_engine()
        with (redirect_stdout(StringIO()), redirect_stderr(StringIO()),
              self.assertRaisesMessage(
                  CommandError, f"Could not rewrap the secrets of mdm.DeviceCommand {failing_db_command.pk}"
              )):
            call_command("rewrap_secrets")
        self.assertEqual(DeviceCommand.objects.get(pk=failing_db_command.pk).kwargs, {"PIN": "yolo$fomo"})
        self.assertEqual(self._decrypt(DeviceCommand.objects.get(pk=db_command.pk), "PIN"), b"123456")

    def test_rewrap_secrets_management_command(self):
        db_command = self._force_command(DeviceLock, kwargs={"Message": "lost"}, secret=b"123456")
        other_db_command = self._force_command(DeviceInformation, kwargs={"yolo": "fomo"})
        self._load_fernet_engine()
        stdout = StringIO()
        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            call_command("rewrap_secrets")
        self.assertIn("DeviceCommand: 1 objects to update", stdout.getvalue())
        self.assertIn("UserCommand: 0 objects to update", stdout.getvalue())
        updated_db_command = DeviceCommand.objects.get(pk=db_command.pk)
        self.assertEqual(updated_db_command.kwargs["PIN"].split("$")[0], "fernet")
        self.assertEqual(self._decrypt(updated_db_command, "PIN"), b"123456")
        self.assertEqual(updated_db_command.kwargs["Message"], "lost")
        self.assertEqual(updated_db_command.updated_at, db_command.updated_at)
        self.assertEqual(DeviceCommand.objects.get(pk=other_db_command.pk).updated_at, other_db_command.updated_at)

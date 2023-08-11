from datetime import datetime, timedelta
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.commands import SetFirmwarePassword
from zentral.contrib.mdm.commands.scheduling import _manage_recovery_password
from zentral.contrib.mdm.models import Channel, Command, Platform, RequestStatus
from .utils import force_blueprint, force_dep_enrollment_session, force_recovery_password_config


class SetFirmwarePasswordCommandTestCase(TestCase):
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

    def test_verify_channel_and_device(self):
        for channel, platform, user_enrollment, apple_silicon, pending_firmware_password, result in (
            (Channel.USER, Platform.MACOS, False, False, None, False),
            (Channel.DEVICE, Platform.IOS, False, False, None, False),
            (Channel.DEVICE, Platform.MACOS, True, False, None, False),
            (Channel.DEVICE, Platform.MACOS, False, True, None, False),
            (Channel.DEVICE, Platform.MACOS, False, False, "012345678", False),
            (Channel.DEVICE, Platform.MACOS, False, False, None, True),
        ):
            self.enrolled_device.platform = platform
            self.enrolled_device.user_enrollment = user_enrollment
            self.enrolled_device.apple_silicon = apple_silicon
            self.enrolled_device.set_pending_firmware_password(pending_firmware_password)
            self.assertEqual(
                SetFirmwarePassword.verify_channel_and_device(channel, self.enrolled_device),
                result
            )

    # process_response

    def test_process_acknowledged_response_password_not_changed(self):
        cmd = SetFirmwarePassword.create_for_automatic_scheduling(Target(self.enrolled_device), "12345678")
        cmd.process_response(
            {"UDID": self.enrolled_device.udid,
             "Status": "Acknowledged",
             "SetFirmwarePassword": {"PasswordChanged": False},
             "CommandUUID": str(cmd.uuid).upper()},
            self.dep_enrollment_session,
            self.mbu
        )
        self.assertEqual(cmd.status, Command.Status.ACKNOWLEDGED)
        self.assertEqual(cmd.db_command.status, Command.Status.ACKNOWLEDGED)
        self.enrolled_device.refresh_from_db()
        self.assertIsNone(self.enrolled_device.pending_firmware_password)
        self.assertIsNone(self.enrolled_device.pending_firmware_password_created_at)
        self.assertEqual(self.enrolled_device.commands.filter(name="RestartDevice").count(), 0)

    def test_process_acknowledged_response_password_changed(self):
        cmd = SetFirmwarePassword.create_for_automatic_scheduling(Target(self.enrolled_device), "12345678")
        now = datetime.utcnow()
        cmd.process_response(
            {"UDID": self.enrolled_device.udid,
             "Status": "Acknowledged",
             "SetFirmwarePassword": {"PasswordChanged": True},
             "CommandUUID": str(cmd.uuid).upper()},
            self.dep_enrollment_session,
            self.mbu
        )
        self.assertEqual(cmd.status, Command.Status.ACKNOWLEDGED)
        self.assertEqual(cmd.db_command.status, Command.Status.ACKNOWLEDGED)
        self.enrolled_device.refresh_from_db()
        self.assertEqual(self.enrolled_device.get_pending_firmware_password(), "12345678")
        self.assertTrue(self.enrolled_device.pending_firmware_password_created_at > now)
        new_db_cmd_qs = self.enrolled_device.commands.filter(name="RestartDevice")
        self.assertEqual(new_db_cmd_qs.count(), 1)
        new_db_cmd = new_db_cmd_qs.first()
        self.assertEqual(new_db_cmd.kwargs, {"NotifyUser": True})

    # _manage_recovery_password

    # see test_set_recovery_lock_command.py too

    def test_manage_recovery_password_pending_firmware_password_noop(self):
        self.enrolled_device.blueprint = force_blueprint(recovery_password_config=force_recovery_password_config())
        self.enrolled_device.set_pending_firmware_password("12345678")
        self.enrolled_device.save()
        self.assertIsNone(_manage_recovery_password(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_manage_recovery_password_first_time_static_ok(self):
        self.enrolled_device.blueprint = force_blueprint(recovery_password_config=force_recovery_password_config(
            static_password="12345678"
        ))
        self.enrolled_device.save()
        cmd = _manage_recovery_password(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(cmd, SetFirmwarePassword)
        self.assertEqual(
            cmd.build_command(),
            {"NewPassword": "12345678"}
        )

    def test_manage_recovery_password_existing_recent_password_firmware_rotation_noop(self):
        self.enrolled_device.blueprint = force_blueprint(recovery_password_config=force_recovery_password_config(
            rotation_interval_days=90,
            rotate_firmware_password=True,
        ))
        self.enrolled_device.set_recovery_password("12345678")
        self.enrolled_device.save()
        self.assertIsNone(_manage_recovery_password(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_manage_recovery_password_existing_old_password_no_firmware_rotation_noop(self):
        self.enrolled_device.blueprint = force_blueprint(recovery_password_config=force_recovery_password_config(
            rotation_interval_days=90,
            rotate_firmware_password=False,
        ))
        self.enrolled_device.set_recovery_password("12345678")
        self.enrolled_device.recovery_password_updated_at -= timedelta(days=91)
        self.enrolled_device.save()
        self.assertIsNone(_manage_recovery_password(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_manage_recovery_password_existing_old_password_firmware_rotation_ok(self):
        self.enrolled_device.blueprint = force_blueprint(recovery_password_config=force_recovery_password_config(
            rotation_interval_days=90,
            rotate_firmware_password=True,
        ))
        self.enrolled_device.set_recovery_password("12345678")
        self.enrolled_device.recovery_password_updated_at -= timedelta(days=91)
        self.enrolled_device.save()
        cmd = _manage_recovery_password(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(cmd, SetFirmwarePassword)
        self.assertEqual(
            cmd.build_command(),
            {"CurrentPassword": "12345678",
             "NewPassword": cmd.load_new_password()}
        )

from datetime import datetime, timedelta
import plistlib
from unittest.mock import patch
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.commands import SetRecoveryLock
from zentral.contrib.mdm.commands.scheduling import _manage_recovery_password
from zentral.contrib.mdm.events import (RecoveryPasswordClearedEvent,
                                        RecoveryPasswordSetEvent,
                                        RecoveryPasswordUpdatedEvent)
from zentral.contrib.mdm.models import Channel, Command, Platform, RequestStatus
from .utils import force_blueprint, force_dep_enrollment_session, force_enrolled_user, force_recovery_password_config


class SetRecoveryLockCommandTestCase(TestCase):
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
        cls.enrolled_device.apple_silicon = True
        cls.enrolled_device.save()

    # verify_channel_and_device

    def test_verify_channel_and_device_ok(self):
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.assertTrue(self.enrolled_device.apple_silicon)
        self.assertTrue(SetRecoveryLock.verify_channel_and_device(
            Channel.DEVICE,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_user_channel_not_ok(self):
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.assertTrue(self.enrolled_device.apple_silicon)
        self.assertFalse(SetRecoveryLock.verify_channel_and_device(
            Channel.USER,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_intel_not_ok(self):
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.enrolled_device.apple_silicon = False
        self.assertFalse(SetRecoveryLock.verify_channel_and_device(
            Channel.DEVICE,
            self.enrolled_device
        ))

    # build_command

    def test_build_command_set_automatic_password(self):
        cmd = SetRecoveryLock.create_for_automatic_scheduling(Target(self.enrolled_device))
        response = cmd.build_http_response(self.dep_enrollment_session)
        cmd_plist = plistlib.loads(response.content)["Command"]
        self.assertEqual(cmd_plist["RequestType"], "SetRecoveryLock")
        self.assertEqual(cmd_plist["NewPassword"], cmd.load_new_password())
        self.assertEqual(len(cmd_plist["NewPassword"]), 12)
        self.assertNotIn("CurrentPassword", cmd_plist)

    def test_build_command_set_static_password(self):
        cmd = SetRecoveryLock.create_for_automatic_scheduling(Target(self.enrolled_device), "12345678")
        response = cmd.build_http_response(self.dep_enrollment_session)
        cmd_plist = plistlib.loads(response.content)["Command"]
        self.assertEqual(cmd_plist["RequestType"], "SetRecoveryLock")
        self.assertEqual(cmd_plist["NewPassword"], "12345678")
        self.assertNotIn("CurrentPassword", cmd_plist)

    def test_build_command_rotate_automatic_password(self):
        self.enrolled_device.set_recovery_password("12345678")
        self.enrolled_device.save()
        cmd = SetRecoveryLock.create_for_automatic_scheduling(Target(self.enrolled_device))
        response = cmd.build_http_response(self.dep_enrollment_session)
        cmd_plist = plistlib.loads(response.content)["Command"]
        self.assertEqual(cmd_plist["RequestType"], "SetRecoveryLock")
        self.assertEqual(cmd_plist["CurrentPassword"], "12345678")
        self.assertEqual(cmd_plist["NewPassword"], cmd.load_new_password())
        self.assertEqual(len(cmd_plist["NewPassword"]), 12)

    def test_build_command_clear_password(self):
        self.enrolled_device.set_recovery_password("12345678")
        self.enrolled_device.save()
        cmd = SetRecoveryLock.create_for_target(Target(self.enrolled_device))
        response = cmd.build_http_response(self.dep_enrollment_session)
        cmd = SetRecoveryLock.create_for_automatic_scheduling(Target(self.enrolled_device))
        cmd_plist = plistlib.loads(response.content)["Command"]
        self.assertEqual(cmd_plist["RequestType"], "SetRecoveryLock")
        self.assertEqual(cmd_plist["CurrentPassword"], "12345678")
        self.assertEqual(cmd_plist["NewPassword"], "")

    # process_response

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_process_acknowledged_response_set_recovery_lock(self, post_event):
        self.assertIsNone(self.enrolled_device.recovery_password)
        self.assertIsNone(self.enrolled_device.recovery_password_updated_at)
        cmd = SetRecoveryLock.create_for_automatic_scheduling(Target(self.enrolled_device), "12345678")
        with self.captureOnCommitCallbacks(execute=True):
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
        self.assertEqual(self.enrolled_device.get_recovery_password(), "12345678")
        self.assertIsNotNone(self.enrolled_device.recovery_password_updated_at)
        # event
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, RecoveryPasswordSetEvent)
        self.assertEqual(
            event.payload,
            {'command': {'request_type': 'SetRecoveryLock',
                         'uuid': str(cmd.uuid)},
             'password_type': 'recovery_lock'}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["machine_serial_number"], self.enrolled_device.serial_number)
        self.assertEqual(metadata["objects"], {"mdm_command": [str(cmd.uuid)]})
        self.assertEqual(set(metadata["tags"]), {"mdm", "recovery_password"})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_process_acknowledged_response_update_recovery_lock(self, post_event):
        self.enrolled_device.set_recovery_password("87654321")
        self.enrolled_device.save()
        cmd = SetRecoveryLock.create_for_automatic_scheduling(Target(self.enrolled_device), "12345678")
        with self.captureOnCommitCallbacks(execute=True):
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
        self.assertEqual(self.enrolled_device.get_recovery_password(), "12345678")
        # event
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, RecoveryPasswordUpdatedEvent)
        self.assertEqual(
            event.payload,
            {'command': {'request_type': 'SetRecoveryLock',
                         'uuid': str(cmd.uuid)},
             'password_type': 'recovery_lock'}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["machine_serial_number"], self.enrolled_device.serial_number)
        self.assertEqual(metadata["objects"], {"mdm_command": [str(cmd.uuid)]})
        self.assertEqual(set(metadata["tags"]), {"mdm", "recovery_password"})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_process_acknowledged_response_clear_recovery_lock(self, post_event):
        self.enrolled_device.set_recovery_password("87654321")
        self.enrolled_device.save()
        cmd = SetRecoveryLock.create_for_target(Target(self.enrolled_device))
        with self.captureOnCommitCallbacks(execute=True):
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
        self.assertIsNone(self.enrolled_device.recovery_password)
        # event
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, RecoveryPasswordClearedEvent)
        self.assertEqual(
            event.payload,
            {'command': {'request_type': 'SetRecoveryLock',
                         'uuid': str(cmd.uuid)},
             'password_type': 'recovery_lock'}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["machine_serial_number"], self.enrolled_device.serial_number)
        self.assertEqual(metadata["objects"], {"mdm_command": [str(cmd.uuid)]})
        self.assertEqual(set(metadata["tags"]), {"mdm", "recovery_password"})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_process_acknowledged_response_noop(self, post_event):
        self.enrolled_device.set_recovery_password("12345678")
        self.enrolled_device.save()
        cmd = SetRecoveryLock.create_for_automatic_scheduling(Target(self.enrolled_device), "12345678")
        with self.captureOnCommitCallbacks(execute=True):
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
        self.assertEqual(self.enrolled_device.get_recovery_password(), "12345678")
        post_event.assert_not_called()

    # _manage_recovery_password

    def test_manage_recovery_password_notnow_noop(self):
        self.assertIsNone(_manage_recovery_password(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.NOT_NOW,
        ))

    def test_manage_recovery_password_ios_noop(self):
        self.enrolled_device.platform = Platform.IOS
        self.enrolled_device.save()
        self.assertIsNone(_manage_recovery_password(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_manage_recovery_password_user_channel_noop(self):
        self.assertIsNone(_manage_recovery_password(
            Target(self.enrolled_device, force_enrolled_user(self.enrolled_device)),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_manage_recovery_password_no_blueprint_noop(self):
        self.enrolled_device.blueprint = None
        self.enrolled_device.save()
        self.assertIsNone(_manage_recovery_password(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_manage_recovery_password_no_recovery_password_config_noop(self):
        self.enrolled_device.blueprint = force_blueprint()
        self.enrolled_device.save()
        self.assertIsNone(self.enrolled_device.blueprint.recovery_password_config)
        self.assertIsNone(_manage_recovery_password(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_manage_recovery_password_existing_password_no_auto_rotation_noop(self):
        self.enrolled_device.blueprint = force_blueprint(recovery_password_config=force_recovery_password_config())
        self.enrolled_device.set_recovery_password("12345678")
        self.enrolled_device.save()
        self.assertEqual(self.enrolled_device.blueprint.recovery_password_config.rotation_interval_days, 0)
        self.assertIsNone(_manage_recovery_password(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_manage_recovery_password_existing_recent_password_auto_rotation_noop(self):
        self.enrolled_device.blueprint = force_blueprint(recovery_password_config=force_recovery_password_config(
            rotation_interval_days=90
        ))
        self.enrolled_device.set_recovery_password("12345678")
        self.enrolled_device.save()
        self.assertIsNone(_manage_recovery_password(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_manage_recovery_password_existing_old_password_auto_rotation_latest_cmd_error_noop(self):
        self.enrolled_device.blueprint = force_blueprint(recovery_password_config=force_recovery_password_config(
            rotation_interval_days=90
        ))
        self.enrolled_device.set_recovery_password("12345678")
        self.enrolled_device.recovery_password_updated_at -= timedelta(days=91)
        self.enrolled_device.save()
        cmd = SetRecoveryLock.create_for_target(Target(self.enrolled_device))
        cmd.process_response(
            {"UDID": self.enrolled_device.udid,
             "Status": "Error",
             "CommandUUID": str(cmd.uuid).upper()},
            self.dep_enrollment_session,
            self.mbu
        )
        self.assertIsNone(_manage_recovery_password(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_manage_recovery_password_existing_old_password_auto_rotation_ok(self):
        self.enrolled_device.blueprint = force_blueprint(recovery_password_config=force_recovery_password_config(
            rotation_interval_days=90
        ))
        self.enrolled_device.set_recovery_password("12345678")
        self.enrolled_device.recovery_password_updated_at -= timedelta(days=91)
        self.enrolled_device.save()
        cmd = SetRecoveryLock.create_for_target(Target(self.enrolled_device))
        cmd.db_command.time = datetime.utcnow() - timedelta(hours=5)
        cmd.db_command.save()
        cmd.process_response(
            {"UDID": self.enrolled_device.udid,
             "Status": "Error",
             "CommandUUID": str(cmd.uuid).upper()},
            self.dep_enrollment_session,
            self.mbu
        )
        cmd = _manage_recovery_password(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(cmd, SetRecoveryLock)
        self.assertEqual(cmd.build_command()["CurrentPassword"], "12345678")

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
        self.assertIsInstance(cmd, SetRecoveryLock)
        self.assertEqual(
            cmd.build_command(),
            {"NewPassword": "12345678"}
        )

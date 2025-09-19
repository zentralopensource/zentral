from datetime import datetime
import plistlib
from unittest.mock import patch
from uuid import uuid4
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.commands import SetAutoAdminPassword
from zentral.contrib.mdm.commands.set_auto_admin_password import generate_password, get_command_kwargs
from zentral.contrib.mdm.events import AdminPasswordUpdatedEvent
from zentral.contrib.mdm.models import Channel, Command, Platform
from zentral.core.secret_engines import decrypt_str
from .utils import force_dep_enrollment_session


class SetAutoAdminPasswordCommandTestCase(TestCase):
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
        cls.enrolled_device.device_information = {
            "AutoSetupAdminAccounts": [
                {"GUID": "yolo", "shortName": "fomo"}
            ]
        }
        cls.enrolled_device.save()

    # generate_password

    def test_generate_password_default_complexity(self):
        pwd = generate_password(17)
        self.assertEqual(len(pwd), 27)

    def test_generate_password_medium_complexity(self):
        pwd = generate_password(2)
        self.assertEqual(len(pwd), 20)

    def test_generate_password_low_complexity(self):
        pwd = generate_password(1)
        self.assertEqual(len(pwd), 13)

    # get_command_kwargs

    def test_get_command_kwargs_pwd(self):
        uuid = uuid4()
        kwargs = get_command_kwargs(uuid, "yolo")
        self.assertIsInstance(kwargs, dict)
        self.assertEqual(list(kwargs.keys()), ["new_password"])
        self.assertEqual(decrypt_str(kwargs["new_password"]), "yolo")

    # verify_channel_and_device

    def test_verify_channel_and_device_ok(self):
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.assertEqual(self.enrolled_device.admin_guid, "yolo")
        self.assertEqual(self.enrolled_device.admin_shortname, "fomo")
        self.enrolled_device.user_enrollment = False
        self.assertTrue(SetAutoAdminPassword.verify_channel_and_device(
            Channel.DEVICE,
            self.enrolled_device,
        ))

    def test_verify_channel_and_device_no_admin_guid_not_ok(self):
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.enrolled_device.device_information = {}
        self.assertIsNone(self.enrolled_device.admin_guid)
        self.assertIsNone(self.enrolled_device.admin_shortname)
        self.enrolled_device.user_enrollment = False
        self.assertFalse(SetAutoAdminPassword.verify_channel_and_device(
            Channel.DEVICE,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_user_channel_not_ok(self):
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.assertEqual(self.enrolled_device.admin_guid, "yolo")
        self.assertEqual(self.enrolled_device.admin_shortname, "fomo")
        self.enrolled_device.user_enrollment = False
        self.assertFalse(SetAutoAdminPassword.verify_channel_and_device(
            Channel.USER,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_user_enrollment_not_ok(self):
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.assertEqual(self.enrolled_device.admin_guid, "yolo")
        self.assertEqual(self.enrolled_device.admin_shortname, "fomo")
        self.enrolled_device.user_enrollment = True
        self.assertFalse(SetAutoAdminPassword.verify_channel_and_device(
            Channel.DEVICE,
            self.enrolled_device
        ))

    # build_command

    def test_build_command_auto_rotation(self):
        cmd = SetAutoAdminPassword.create_for_auto_rotation(Target(self.enrolled_device), 60)
        response = cmd.build_http_response(self.dep_enrollment_session)
        cmd_plist = plistlib.loads(response.content)["Command"]
        self.assertEqual(cmd_plist["RequestType"], "SetAutoAdminPassword")
        self.assertEqual(cmd_plist["GUID"], "yolo")
        pwd_hash = plistlib.loads(cmd_plist["passwordHash"])
        self.assertIn("SALTED-SHA512-PBKDF2", pwd_hash)

    def test_build_command_auto_rotation_already_scheduled(self):
        cmd = SetAutoAdminPassword.create_for_auto_rotation(Target(self.enrolled_device), 60)
        self.assertIsInstance(cmd, SetAutoAdminPassword)
        # a command is already scheduled
        self.assertIsNone(SetAutoAdminPassword.create_for_auto_rotation(Target(self.enrolled_device), 60))

    def test_build_command_auto_rotation_existing_sent_command(self):
        cmd = SetAutoAdminPassword.create_for_auto_rotation(Target(self.enrolled_device), 60)
        self.assertIsInstance(cmd, SetAutoAdminPassword)
        cmd.db_command.time = datetime.utcnow()
        cmd.db_command.save()
        cmd2 = SetAutoAdminPassword.create_for_auto_rotation(Target(self.enrolled_device), 60)
        self.assertIsInstance(cmd2, SetAutoAdminPassword)

    # process_response

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_process_acknowledged_response_set_admin_password(self, post_event):
        self.assertIsNone(self.enrolled_device.admin_password)
        self.assertIsNone(self.enrolled_device.admin_password_updated_at)
        cmd = SetAutoAdminPassword.create_for_auto_rotation(Target(self.enrolled_device), 1)
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
        self.assertEqual(self.enrolled_device.get_admin_password(), cmd.load_new_password())
        self.assertIsNotNone(self.enrolled_device.admin_password_updated_at)
        # event
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, AdminPasswordUpdatedEvent)
        self.assertEqual(
            event.payload,
            {'command': {'request_type': 'SetAutoAdminPassword',
                         'uuid': str(cmd.uuid)}}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["machine_serial_number"], self.enrolled_device.serial_number)
        self.assertEqual(metadata["objects"], {"mdm_command": [str(cmd.uuid)]})
        self.assertEqual(set(metadata["tags"]), {"mdm", "admin_password"})

from datetime import datetime
import os.path
import plistlib
import uuid
from unittest.mock import patch
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.models import Channel, CommandStatus, DeviceCommand, EnrolledUser, UserCommand
from zentral.contrib.mdm.commands.base import get_command, load_command
from zentral.contrib.mdm.commands.profile_list import ProfileList
from .utils import force_dep_enrollment_session


class TestMDMCommandsBase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.dep_enrollment_session, _, _ = force_dep_enrollment_session(
            cls.mbu, authenticated=True, completed=True, realm_user=True
        )
        cls.enrolled_device = cls.dep_enrollment_session.enrolled_device
        cls.enrolled_device.save()
        cls.enrolled_user = EnrolledUser.objects.create(
            enrolled_device=cls.enrolled_device,
            user_id=str(uuid.uuid4()).upper(),
            long_name=get_random_string(12),
            short_name=get_random_string(12),
            token=get_random_string(12).encode("utf-8"),
        )

    # load_command

    def test_load_device_command_unknown_command_model(self):
        db_command = DeviceCommand.objects.create(
            uuid=uuid.UUID("535be08d-2187-4f08-b278-99327cee2e00"),
            enrolled_device=self.enrolled_device,
            name="Ceci n'est pas un nom de commande"
        )
        with self.assertRaises(ValueError) as cm:
            load_command(db_command)
        self.assertEqual(cm.exception.args[0], "Unknown command model class: Ceci n'est pas un nom de commande")

    def test_load_user_command_unknown_command_model(self):
        db_command = UserCommand.objects.create(
            uuid=uuid.UUID("535be08d-2187-4f08-b278-99327cee2e01"),
            enrolled_user=self.enrolled_user,
            name="Ceci n'est pas un nom de commande"
        )
        with self.assertRaises(ValueError) as cm:
            load_command(db_command)
        self.assertEqual(cm.exception.args[0], "Unknown command model class: Ceci n'est pas un nom de commande")

    def test_load_device_command_with_result(self):
        result = plistlib.load(
            open(
                os.path.join(os.path.dirname(__file__), "testdata/profile_list.plist"),
                "rb",
            )
        )
        result["UDID"] = self.enrolled_device.udid.upper()
        result_time = datetime.utcnow()
        db_command = DeviceCommand.objects.create(
            uuid=result["CommandUUID"],
            enrolled_device=self.enrolled_device,
            name="ProfileList",
            result=plistlib.dumps(result),
            result_time=result_time,
            status="Acknowledged"
        )
        db_command.refresh_from_db()  # uuid str → UUID
        cmd = load_command(db_command)
        self.assertIsInstance(cmd, ProfileList)
        self.assertEqual(cmd.response, result)
        self.assertEqual(cmd.result_time, result_time)
        self.assertEqual(cmd.status, CommandStatus.Acknowledged)
        self.assertEqual(cmd.uuid, uuid.UUID(result["CommandUUID"]))

    # test_get_command

    @patch("zentral.contrib.mdm.commands.base.logger.error")
    def test_get_device_command_does_not_exist(self, logger_error):
        unknown_uuid = uuid.uuid4()
        cmd = get_command(Channel.Device, unknown_uuid)
        self.assertIsNone(cmd)
        logger_error.assert_called_once_with(
            "Unknown command: %s %s",
            "Device",
            unknown_uuid
        )

    @patch("zentral.contrib.mdm.commands.base.logger.error")
    def test_get_user_command_does_not_exist(self, logger_error):
        unknown_uuid = uuid.uuid4()
        cmd = get_command(Channel.User, unknown_uuid)
        self.assertIsNone(cmd)
        logger_error.assert_called_once_with(
            "Unknown command: %s %s",
            "User",
            unknown_uuid
        )

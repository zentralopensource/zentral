import plistlib
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.commands import CustomCommand
from zentral.contrib.mdm.commands.scheduling import _get_next_queued_command
from zentral.contrib.mdm.models import Channel, CommandStatus, RequestStatus
from .utils import force_dep_enrollment_session


class CustomCommandTestCase(TestCase):
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
        for channel in (Channel.Device, Channel.User):
            self.assertTrue(CustomCommand.verify_channel_and_device(channel, self.enrolled_device))

    # load_kwargs

    def test_load_kwargs(self):
        cmd_payload = {
            "RequestType": "InstalledApplicationList",
            "ManagedAppsOnly": False
        }
        cmd = CustomCommand.create_for_device(
            self.enrolled_device,
            kwargs={"command": plistlib.dumps(cmd_payload).decode("utf-8")},
            queue=True
        )
        self.assertEqual(cmd.command, {"ManagedAppsOnly": False})
        self.assertEqual(cmd.request_type, "InstalledApplicationList")

    # build_command

    def test_build_command(self):
        cmd_payload = {
            "RequestType": "InstalledApplicationList",
            "ManagedAppsOnly": False
        }
        cmd = CustomCommand.create_for_device(
            self.enrolled_device,
            kwargs={"command": plistlib.dumps(cmd_payload).decode("utf-8")},
            queue=True
        )
        self.assertEqual(cmd.build_command(), {"ManagedAppsOnly": False})

    # process_response

    def test_process_acknowledged_response(self):
        cmd_payload = {
            "RequestType": "InstalledApplicationList",
            "ManagedAppsOnly": False
        }
        cmd = CustomCommand.create_for_device(
            self.enrolled_device,
            kwargs={"command": plistlib.dumps(cmd_payload).decode("utf-8")},
        )
        cmd.process_response(
            {"UDID": self.enrolled_device.udid,
             "Status": "Acknowledged",
             "CommandUUID": str(cmd.uuid).upper(),
             "InstalledApplicationList": []},
            self.dep_enrollment_session,
            self.mbu
        )
        cmd.db_command.refresh_from_db()
        self.assertEqual(cmd.status, CommandStatus.Acknowledged)
        self.assertEqual(cmd.db_command.status, CommandStatus.Acknowledged.value)

    def test_process_notnow_response(self):
        cmd_payload = {
            "RequestType": "InstalledApplicationList",
            "ManagedAppsOnly": False
        }
        cmd = CustomCommand.create_for_device(
            self.enrolled_device,
            kwargs={"command": plistlib.dumps(cmd_payload).decode("utf-8")},
        )
        cmd.process_response(
            {"UDID": self.enrolled_device.udid,
             "Status": "NotNow",
             "CommandUUID": str(cmd.uuid).upper()},
            self.dep_enrollment_session,
            self.mbu
        )
        cmd.db_command.refresh_from_db()
        self.assertEqual(cmd.status, CommandStatus.NotNow)
        self.assertEqual(cmd.db_command.status, CommandStatus.NotNow.value)
        self.assertIsNone(cmd.db_command.result)

    def test_process_rescheduled_acknowledged_response(self):
        cmd_payload = {
            "RequestType": "InstalledApplicationList",
            "ManagedAppsOnly": False
        }
        cmd = CustomCommand.create_for_device(
            self.enrolled_device,
            kwargs={"command": plistlib.dumps(cmd_payload).decode("utf-8")},
        )
        # first not now
        cmd.process_response(
            {"UDID": self.enrolled_device.udid,
             "Status": "NotNow",
             "CommandUUID": str(cmd.uuid).upper()},
            self.dep_enrollment_session,
            self.mbu
        )
        # then acknowledged
        cmd.process_response(
            {"UDID": self.enrolled_device.udid,
             "Status": "Acknowledged",
             "CommandUUID": str(cmd.uuid).upper(),
             "InstalledApplicationList": []},
            self.dep_enrollment_session,
            self.mbu
        )
        cmd.db_command.refresh_from_db()
        self.assertEqual(cmd.status, CommandStatus.Acknowledged)
        self.assertEqual(cmd.db_command.status, CommandStatus.Acknowledged.value)
        result = plistlib.loads(cmd.db_command.result)
        self.assertEqual(result["Status"], CommandStatus.Acknowledged.value)

    # _get_next_queued_command

    def test_not_now_command_not_now(self):
        cmd = CustomCommand.create_for_device(
            self.enrolled_device,
            kwargs={"command": plistlib.dumps({"RequestType": "InstalledApplicationList"}).decode("utf-8")},
        )
        cmd.db_command.status = CommandStatus.NotNow.value
        cmd.db_command.save()
        self.assertIsNone(_get_next_queued_command(
            Channel.Device, RequestStatus.NotNow,
            self.dep_enrollment_session,
            self.enrolled_device,
            None,
        ))

    def test_not_now_custom_command_rescheduled(self):
        cmd = CustomCommand.create_for_device(
            self.enrolled_device,
            kwargs={"command": plistlib.dumps({"RequestType": "InstalledApplicationList"}).decode("utf-8")},
        )
        cmd.db_command.status = CommandStatus.NotNow.value
        cmd.db_command.save()
        fetched_cmd = _get_next_queued_command(
            Channel.Device, RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            None,
        )
        self.assertEqual(fetched_cmd, cmd)

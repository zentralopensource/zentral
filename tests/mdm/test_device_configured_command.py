from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.commands import DeviceConfigured
from zentral.contrib.mdm.commands.utils import _finish_dep_enrollment_configuration
from zentral.contrib.mdm.models import Channel, CommandStatus, RequestStatus
from .utils import force_dep_enrollment_session


class DeviceConfiguredCommandTestCase(TestCase):
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
        self.enrolled_device.awaiting_configuration = True
        self.assertTrue(DeviceConfigured.verify_channel_and_device(
            Channel.Device,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_user_channel_not_ok(self):
        self.enrolled_device.awaiting_configuration = True
        self.assertFalse(DeviceConfigured.verify_channel_and_device(
            Channel.User,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_awaiting_configuration_none_not_ok(self):
        self.assertIsNone(self.enrolled_device.awaiting_configuration)
        self.assertFalse(DeviceConfigured.verify_channel_and_device(
            Channel.Device,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_awaiting_configuration_false_not_ok(self):
        self.enrolled_device.awaiting_configuration = False
        self.assertFalse(DeviceConfigured.verify_channel_and_device(
            Channel.Device,
            self.enrolled_device
        ))

    # build_command

    def test_build_command(self):
        self.enrolled_device.awaiting_configuration = True
        cmd = DeviceConfigured.create_for_device(
            self.enrolled_device,
            queue=True
        )
        self.assertEqual(cmd.build_command(), {})

    # process_response

    def test_process_acknowledged_response(self):
        self.enrolled_device.awaiting_configuration = True
        cmd = DeviceConfigured.create_for_device(self.enrolled_device)
        cmd.process_response(
            {"UDID": self.enrolled_device.udid,
             "Status": "Acknowledged",
             "CommandUUID": str(cmd.uuid).upper()},
            self.dep_enrollment_session,
            self.mbu
        )
        cmd.db_command.refresh_from_db()
        self.assertEqual(cmd.status, CommandStatus.Acknowledged)
        self.assertEqual(cmd.db_command.status, CommandStatus.Acknowledged.value)
        self.enrolled_device.refresh_from_db()
        self.assertFalse(self.enrolled_device.awaiting_configuration)

    # _finish_dep_enrollment_configuration

    def test_device_configured_already_done(self):
        self.enrolled_device.awaiting_configuration = False
        self.assertIsNone(_finish_dep_enrollment_configuration(
            Channel.Device, RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            None
        ))

    def test_device_configured_notnow_noop(self):
        self.enrolled_device.awaiting_configuration = True
        self.assertIsNone(_finish_dep_enrollment_configuration(
            Channel.Device, RequestStatus.NotNow,
            self.dep_enrollment_session,
            self.enrolled_device,
            None
        ))

    def test_device_configured(self):
        self.enrolled_device.awaiting_configuration = True
        command = _finish_dep_enrollment_configuration(
            Channel.Device, RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            None
        )
        self.assertIsInstance(command, DeviceConfigured)
        self.assertEqual(command.channel, Channel.Device)

from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.commands import DeviceConfigured
from zentral.contrib.mdm.commands.scheduling import _finish_dep_enrollment_configuration
from zentral.contrib.mdm.models import Channel, Command, RequestStatus
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
            Channel.DEVICE,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_user_channel_not_ok(self):
        self.enrolled_device.awaiting_configuration = True
        self.assertFalse(DeviceConfigured.verify_channel_and_device(
            Channel.USER,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_awaiting_configuration_none_not_ok(self):
        self.assertIsNone(self.enrolled_device.awaiting_configuration)
        self.assertFalse(DeviceConfigured.verify_channel_and_device(
            Channel.DEVICE,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_awaiting_configuration_false_not_ok(self):
        self.enrolled_device.awaiting_configuration = False
        self.assertFalse(DeviceConfigured.verify_channel_and_device(
            Channel.DEVICE,
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
        self.assertEqual(cmd.status, Command.Status.ACKNOWLEDGED)
        self.assertEqual(cmd.db_command.status, Command.Status.ACKNOWLEDGED)
        self.enrolled_device.refresh_from_db()
        self.assertFalse(self.enrolled_device.awaiting_configuration)

    # _finish_dep_enrollment_configuration

    def test_device_configured_already_done(self):
        self.enrolled_device.awaiting_configuration = False
        self.assertIsNone(_finish_dep_enrollment_configuration(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))

    def test_device_configured_notnow_ok(self):
        self.enrolled_device.awaiting_configuration = True
        command = _finish_dep_enrollment_configuration(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.NOT_NOW,
        )
        self.assertIsInstance(command, DeviceConfigured)
        self.assertEqual(command.channel, Channel.DEVICE)

    def test_device_configured(self):
        self.enrolled_device.awaiting_configuration = True
        command = _finish_dep_enrollment_configuration(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(command, DeviceConfigured)
        self.assertEqual(command.channel, Channel.DEVICE)

import plistlib
from unittest.mock import patch
from uuid import uuid4

from django.test import TestCase
from django.utils.crypto import get_random_string

from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.commands import DeviceLock
from zentral.contrib.mdm.events import (
    DeviceLockPinSetEvent,
)
from zentral.contrib.mdm.models import Channel, Command, Platform

from .utils import force_dep_enrollment_session


class DeviceLockCommandTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.dep_enrollment_session, cls.device_udid, cls.serial_number = (
            force_dep_enrollment_session(
                cls.mbu,
                authenticated=True,
                completed=True,
            )
        )
        cls.enrolled_device = cls.dep_enrollment_session.enrolled_device

    # verify_channel_and_device

    def test_verify_channel_and_device_ok(self):
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.enrolled_device.user_enrollment = False
        self.assertTrue(
            DeviceLock.verify_channel_and_device(Channel.DEVICE, self.enrolled_device)
        )

    def test_verify_channel_and_device_user_channel_not_ok(self):
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.enrolled_device.user_enrollment = False
        self.assertFalse(
            DeviceLock.verify_channel_and_device(Channel.USER, self.enrolled_device)
        )

    def test_verify_channel_and_device_user_enrollment_macos_no_ok(self):
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.enrolled_device.user_enrollment = True
        self.assertFalse(
            DeviceLock.verify_channel_and_device(Channel.DEVICE, self.enrolled_device)
        )

    def test_verify_channel_and_device_user_enrollment_ios_ok(self):
        self.enrolled_device.platform = Platform.IOS
        self.enrolled_device.user_enrollment = True
        self.assertTrue(
            DeviceLock.verify_channel_and_device(Channel.DEVICE, self.enrolled_device)
        )

    def test_verify_channel_and_device_user_enrollment_ipados_ok(self):
        self.enrolled_device.platform = Platform.IPADOS
        self.enrolled_device.user_enrollment = True
        self.assertTrue(
            DeviceLock.verify_channel_and_device(Channel.DEVICE, self.enrolled_device)
        )

    def test_build_command(self):
        self.enrolled_device.platform = Platform.MACOS
        form = DeviceLock.form_class(
            {}, channel=Channel.DEVICE, enrolled_device=self.enrolled_device
        )
        uuid = uuid4()
        cmd = DeviceLock.create_for_device(
            self.enrolled_device,
            kwargs=form.get_command_kwargs_with_data(
                uuid,
                {"pin": "123456", "message": "foobar", "phone_number": "+0049404040"},
            ),
            uuid=uuid,
        )
        command = cmd.build_command()
        self.assertEqual(
            command,
            {"PIN": "123456", "Message": "foobar", "PhoneNumber": "+0049404040"},
        )
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(payload["RequestType"], "DeviceLock")

    # process_response
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_process_acknowledged_response_set_device_lock(self, post_event):
        self.enrolled_device.platform = Platform.MACOS
        form = DeviceLock.form_class(
            {}, channel=Channel.DEVICE, enrolled_device=self.enrolled_device
        )
        uuid = uuid4()
        cmd = DeviceLock.create_for_device(
            self.enrolled_device,
            kwargs=form.get_command_kwargs_with_data(uuid, {"pin": "123456"}),
            uuid=uuid,
        )
        with self.captureOnCommitCallbacks(execute=True):
            cmd.process_response(
                {
                    "UDID": self.enrolled_device.udid,
                    "Status": "Acknowledged",
                    "CommandUUID": str(cmd.uuid).upper(),
                },
                self.dep_enrollment_session,
                self.mbu,
            )
        cmd.db_command.refresh_from_db()
        self.assertEqual(cmd.status, Command.Status.ACKNOWLEDGED)
        self.assertEqual(cmd.db_command.status, Command.Status.ACKNOWLEDGED)
        self.enrolled_device.refresh_from_db()
        self.assertEqual(self.enrolled_device.get_device_lock_pin(), "123456")
        self.assertIsNotNone(self.enrolled_device.device_lock_pin_updated_at)

        # event
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, DeviceLockPinSetEvent)
        self.assertEqual(
            event.payload,
            {
                "command": {"request_type": "DeviceLock", "uuid": str(cmd.uuid)},
            },
        )
        metadata = event.metadata.serialize()
        self.assertEqual(
            metadata["machine_serial_number"], self.enrolled_device.serial_number
        )
        self.assertEqual(metadata["objects"], {"mdm_command": [str(cmd.uuid)]})
        self.assertEqual(set(metadata["tags"]), {"mdm", "device_lock_pin"})

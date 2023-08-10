from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.commands import RestartDevice
from zentral.contrib.mdm.models import Channel, Platform
from .utils import force_dep_enrollment_session


class RestartDeviceCommandTestCase(TestCase):
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
        for channel, user_enrollment, supervised, platform, result in (
            (Channel.USER, False, True, Platform.MACOS, False),
            (Channel.DEVICE, True, False, Platform.MACOS, False),
            (Channel.DEVICE, False, False, Platform.IOS, False),
            (Channel.DEVICE, False, True, Platform.IOS, True),
            (Channel.DEVICE, False, False, Platform.IOS, False),
            (Channel.DEVICE, False, False, Platform.MACOS, True),
            (Channel.DEVICE, False, True, Platform.MACOS, True),
        ):
            self.enrolled_device.user_enrollment = user_enrollment
            self.enrolled_device.supervised = supervised
            self.enrolled_device.platform = platform
            self.assertEqual(
                RestartDevice.verify_channel_and_device(channel, self.enrolled_device),
                result
            )

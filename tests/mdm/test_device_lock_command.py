from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.commands import DeviceLock
from zentral.contrib.mdm.models import Channel, Platform
from .utils import force_dep_enrollment_session


class DeviceLockCommandTestCase(TestCase):
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
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.enrolled_device.user_enrollment = False
        self.assertTrue(DeviceLock.verify_channel_and_device(
            Channel.DEVICE,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_user_channel_not_ok(self):
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.enrolled_device.user_enrollment = False
        self.assertFalse(DeviceLock.verify_channel_and_device(
            Channel.USER,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_user_enrollment_macos_no_ok(self):
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.enrolled_device.user_enrollment = True
        self.assertFalse(DeviceLock.verify_channel_and_device(
            Channel.DEVICE,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_user_enrollment_ios_ok(self):
        self.enrolled_device.platform = Platform.IOS
        self.enrolled_device.user_enrollment = True
        self.assertTrue(DeviceLock.verify_channel_and_device(
            Channel.DEVICE,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_user_enrollment_ipados_ok(self):
        self.enrolled_device.platform = Platform.IPADOS
        self.enrolled_device.user_enrollment = True
        self.assertTrue(DeviceLock.verify_channel_and_device(
            Channel.DEVICE,
            self.enrolled_device
        ))

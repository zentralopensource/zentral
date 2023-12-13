import plistlib
from uuid import uuid4
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.commands import EraseDevice
from zentral.contrib.mdm.models import Channel, Platform
from .utils import force_dep_enrollment_session


class EraseDeviceCommandTestCase(TestCase):
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
        self.assertTrue(EraseDevice.verify_channel_and_device(
            Channel.DEVICE,
            self.enrolled_device
        ))

    def test_verify_channel_and_device_user_channel_not_ok(self):
        self.assertEqual(self.enrolled_device.platform, Platform.MACOS)
        self.assertFalse(EraseDevice.verify_channel_and_device(
            Channel.USER,
            self.enrolled_device
        ))

    # build_command

    def test_build_command_default(self):
        self.enrolled_device.apple_silicon = True
        form = EraseDevice.form_class(
            {}, channel=Channel.DEVICE, enrolled_device=self.enrolled_device
        )
        self.assertTrue(form.is_valid())
        for field in ("disallow_proximity_setup", "preserve_data_plan", "pin"):
            self.assertNotIn(field, form.fields)
        uuid = uuid4()
        cmd = EraseDevice.create_for_device(
            self.enrolled_device,
            kwargs=form.get_command_kwargs(uuid),
            uuid=uuid
        )
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(
            payload,
            {"RequestType": "EraseDevice"}
        )

    def test_build_command_ios_fields_required(self):
        self.enrolled_device.platform = Platform.IOS
        form = EraseDevice.form_class(
            {}, channel=Channel.DEVICE, enrolled_device=self.enrolled_device
        )
        self.assertFalse(form.is_valid())
        self.assertNotIn("pin", form.fields)
        for field in ("disallow_proximity_setup", "preserve_data_plan"):
            self.assertEqual(len(form.errors[field]), 1)
            self.assertEqual(str(form.errors[field][0]), "This field is required.")

    def test_build_command_ios(self):
        self.enrolled_device.platform = Platform.IOS
        form = EraseDevice.form_class(
            {"disallow_proximity_setup": True,
             "preserve_data_plan": True},
            channel=Channel.DEVICE, enrolled_device=self.enrolled_device
        )
        self.assertTrue(form.is_valid())
        self.assertNotIn("pin", form.fields)
        uuid = uuid4()
        cmd = EraseDevice.create_for_device(
            self.enrolled_device,
            kwargs=form.get_command_kwargs(uuid),
            uuid=uuid
        )
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(
            payload,
            {"RequestType": "EraseDevice",
             "DisallowProximitySetup": True,
             "PreserveDataPlan": True}
        )

    def test_build_command_t1_pin_required(self):
        form = EraseDevice.form_class(
            {}, channel=Channel.DEVICE, enrolled_device=self.enrolled_device
        )
        self.assertFalse(form.is_valid())
        for field in ("disallow_proximity_setup", "preserve_data_plan"):
            self.assertNotIn(field, form.fields)
        self.assertEqual(len(form.errors["pin"]), 1)
        self.assertEqual(str(form.errors["pin"][0]), "This field is required.")

    def test_build_command_t1(self):
        form = EraseDevice.form_class(
            {"pin": "abc123"}, channel=Channel.DEVICE, enrolled_device=self.enrolled_device
        )
        self.assertTrue(form.is_valid())
        for field in ("disallow_proximity_setup", "preserve_data_plan"):
            self.assertNotIn(field, form.fields)
        uuid = uuid4()
        cmd = EraseDevice.create_for_device(
            self.enrolled_device,
            kwargs=form.get_command_kwargs(uuid),
            uuid=uuid
        )
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(
            payload,
            {"RequestType": "EraseDevice",
             "PIN": "abc123"}
        )

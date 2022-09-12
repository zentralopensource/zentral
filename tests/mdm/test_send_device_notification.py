import io
from unittest.mock import patch, Mock
from django.core.management import call_command
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from .utils import force_dep_enrollment_session, force_push_certificate


class MDMSendDeviceNotificationTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.push_certificate = force_push_certificate(with_material=True, reduced_key_size=False)

    @patch("zentral.contrib.mdm.apns.httpx.Client.post")
    def test_send_device_notification_ok(self, post):
        mocked_response = Mock()
        mocked_response.status_code = 200
        post.return_value = mocked_response
        _, device_udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        out = io.StringIO()
        call_command('send_device_notification', stdout=out)
        self.assertEqual(out.getvalue(), f"Device {serial_number} {device_udid} OK\n")

    def test_send_device_notification_skipped(self):
        _, device_udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True
        )
        out = io.StringIO()
        call_command('send_device_notification', stdout=out)
        self.assertEqual(out.getvalue(), f"Device {serial_number} {device_udid} Skipped\n")

    @patch("zentral.contrib.mdm.apns.httpx.Client.post")
    def test_send_device_notification_failure(self, post):
        mocked_response = Mock()
        mocked_response.status_code = 400
        post.return_value = mocked_response
        _, device_udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        out = io.StringIO()
        call_command('send_device_notification', stdout=out)
        self.assertEqual(out.getvalue(), f"Device {serial_number} {device_udid} Failure\n")

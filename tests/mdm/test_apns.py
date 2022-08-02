from unittest.mock import patch, Mock
from django.test import TestCase
from django.utils.crypto import get_random_string
import httpx
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.apns import APNSClient
from zentral.contrib.mdm.events import MDMDeviceNotificationEvent
from .utils import force_dep_enrollment_session, force_enrolled_user, force_push_certificate


class MDMAPNSTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.push_certificate = force_push_certificate(with_material=True, reduced_key_size=False)

    def test_apns_client_init_cert_bytes(self):
        self.assertIsInstance(self.push_certificate.certificate, bytes)
        client = APNSClient(self.push_certificate)
        self.assertIsInstance(client.client, httpx.Client)
        self.assertEqual(client.client.base_url, "https://api.push.apple.com")

    def test_apns_client_init_cert_memoryview(self):
        push_certificate = force_push_certificate(with_material=True, reduced_key_size=False)
        push_certificate.refresh_from_db()
        self.assertIsInstance(push_certificate.certificate, memoryview)
        client = APNSClient(push_certificate)
        self.assertIsInstance(client.client, httpx.Client)
        self.assertEqual(client.client.base_url, "https://api.push.apple.com")

    def test_apns_send_device_notification_wrong_push_certificate(self):
        client = APNSClient(self.push_certificate)
        # session with a different push certificate
        session, _, _ = force_dep_enrollment_session(self.mbu, authenticated=True, completed=True)
        with self.assertRaises(ValueError) as cm:
            client.send_device_notification(session.enrolled_device)
        self.assertEqual(
            cm.exception.args[0],
            f"Enrolled device {session.enrolled_device.pk} has a different push certificate",
        )

    def test_apns_send_user_notification_wrong_push_certificate(self):
        client = APNSClient(self.push_certificate)
        # session with a different push certificate
        session, _, _ = force_dep_enrollment_session(self.mbu, authenticated=True, completed=True)
        enrolled_user = force_enrolled_user(session.enrolled_device)
        with self.assertRaises(ValueError) as cm:
            client.send_user_notification(enrolled_user)
        self.assertEqual(
            cm.exception.args[0],
            f"Enrolled device {session.enrolled_device.pk} has a different push certificate",
        )

    def test_apns_send_device_notification_cannot_be_poked(self):
        client = APNSClient(self.push_certificate)
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        session.enrolled_device.token = None
        with self.assertRaises(ValueError) as cm:
            client.send_device_notification(session.enrolled_device)
        self.assertEqual(
            cm.exception.args[0],
            f"Cannot send notification to enrolled device {session.enrolled_device.pk}",
        )

    def test_apns_send_user_notification_cannot_be_poked(self):
        client = APNSClient(self.push_certificate)
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        session.enrolled_device.token = None
        enrolled_user = force_enrolled_user(session.enrolled_device)
        with self.assertRaises(ValueError) as cm:
            client.send_user_notification(enrolled_user)
        self.assertEqual(
            cm.exception.args[0],
            f"Cannot send notification to enrolled device {session.enrolled_device.pk}",
        )

    @patch("zentral.contrib.mdm.apns.time.sleep")
    @patch("zentral.contrib.mdm.apns.httpx.Client.post")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_apns_send_device_notification_no_retries_failure(self, post_event, post, sleep):
        mocked_reponse = Mock()
        mocked_reponse.status_code = 400  # no retries if < 500
        post.return_value = mocked_reponse
        client = APNSClient(self.push_certificate)
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        status = client.send_device_notification(session.enrolled_device)
        self.assertEqual(status, "failure")
        sleep.assert_not_called()
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MDMDeviceNotificationEvent)
        self.assertEqual(event.metadata.machine_serial_number, session.enrolled_device.serial_number)
        self.assertEqual(event.payload["status"], "failure")
        self.assertNotIn("user_id", event.payload)

    @patch("zentral.contrib.mdm.apns.time.sleep")
    @patch("zentral.contrib.mdm.apns.httpx.Client.post")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_apns_send_device_notification_retries_failure(self, post_event, post, sleep):
        mocked_reponse = Mock()
        mocked_reponse.status_code = 500  # retries if >= 500
        post.return_value = mocked_reponse
        client = APNSClient(self.push_certificate)
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        status = client.send_device_notification(session.enrolled_device)
        self.assertEqual(status, "failure")
        self.assertEqual(len(sleep.call_args), client.max_retries)
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MDMDeviceNotificationEvent)
        self.assertEqual(event.metadata.machine_serial_number, session.enrolled_device.serial_number)
        self.assertEqual(event.payload["status"], "failure")
        self.assertNotIn("user_id", event.payload)

    @patch("zentral.contrib.mdm.apns.time.sleep")
    @patch("zentral.contrib.mdm.apns.httpx.Client.post")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_apns_send_device_notification_ok(self, post_event, post, sleep):
        mocked_reponse = Mock()
        mocked_reponse.status_code = 200
        post.return_value = mocked_reponse
        client = APNSClient(self.push_certificate)
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        status = client.send_device_notification(session.enrolled_device)
        self.assertEqual(status, "success")
        sleep.assert_not_called()
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MDMDeviceNotificationEvent)
        self.assertEqual(event.metadata.machine_serial_number, session.enrolled_device.serial_number)
        self.assertEqual(event.payload["status"], "success")
        self.assertNotIn("user_id", event.payload)

    @patch("zentral.contrib.mdm.apns.time.sleep")
    @patch("zentral.contrib.mdm.apns.httpx.Client.post")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_apns_send_user_notification_no_retries_failure(self, post_event, post, sleep):
        mocked_reponse = Mock()
        mocked_reponse.status_code = 400  # no retries if < 500
        post.return_value = mocked_reponse
        client = APNSClient(self.push_certificate)
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        enrolled_user = force_enrolled_user(session.enrolled_device)
        status = client.send_user_notification(enrolled_user)
        self.assertEqual(status, "failure")
        sleep.assert_not_called()
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MDMDeviceNotificationEvent)
        self.assertEqual(event.metadata.machine_serial_number, session.enrolled_device.serial_number)
        self.assertEqual(event.payload["status"], "failure")
        self.assertEqual(event.payload["user_id"], enrolled_user.user_id)

    @patch("zentral.contrib.mdm.apns.time.sleep")
    @patch("zentral.contrib.mdm.apns.httpx.Client.post")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_apns_send_user_notification_retries_failure(self, post_event, post, sleep):
        mocked_reponse = Mock()
        mocked_reponse.status_code = 500  # retries if >= 500
        post.return_value = mocked_reponse
        client = APNSClient(self.push_certificate)
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        enrolled_user = force_enrolled_user(session.enrolled_device)
        status = client.send_user_notification(enrolled_user)
        self.assertEqual(status, "failure")
        self.assertEqual(len(sleep.call_args), client.max_retries)
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MDMDeviceNotificationEvent)
        self.assertEqual(event.metadata.machine_serial_number, session.enrolled_device.serial_number)
        self.assertEqual(event.payload["status"], "failure")
        self.assertEqual(event.payload["user_id"], enrolled_user.user_id)

    @patch("zentral.contrib.mdm.apns.time.sleep")
    @patch("zentral.contrib.mdm.apns.httpx.Client.post")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_apns_send_user_notification_ok(self, post_event, post, sleep):
        mocked_reponse = Mock()
        mocked_reponse.status_code = 200
        post.return_value = mocked_reponse
        client = APNSClient(self.push_certificate)
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        enrolled_user = force_enrolled_user(session.enrolled_device)
        status = client.send_user_notification(enrolled_user)
        self.assertEqual(status, "success")
        sleep.assert_not_called()
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MDMDeviceNotificationEvent)
        self.assertEqual(event.metadata.machine_serial_number, session.enrolled_device.serial_number)
        self.assertEqual(event.payload["status"], "success")
        self.assertEqual(event.payload["user_id"], enrolled_user.user_id)

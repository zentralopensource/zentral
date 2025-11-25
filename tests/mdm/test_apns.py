from datetime import datetime, timedelta
from unittest.mock import patch, Mock
from django.test import TestCase
from django.utils.crypto import get_random_string
import httpx
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.apns import (apns_client_cache, APNSClient,
                                      send_enrolled_device_notification, send_enrolled_user_notification)
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
        client = APNSClient.from_push_certificate(self.push_certificate)
        self.assertIsInstance(client.client, httpx.Client)
        self.assertEqual(client.client.base_url, "https://api.push.apple.com")

    def test_apns_client_init_cert_memoryview(self):
        push_certificate = force_push_certificate(with_material=True, reduced_key_size=False)
        push_certificate.refresh_from_db()
        self.assertIsInstance(push_certificate.certificate, memoryview)
        client = APNSClient.from_push_certificate(push_certificate)
        self.assertEqual(client.topic, push_certificate.topic)
        self.assertEqual(client.not_after, push_certificate.not_after)
        self.assertIsInstance(client.client, httpx.Client)
        self.assertEqual(client.client.base_url, "https://api.push.apple.com")

    def test_apns_client_cache_no_client(self):
        client = apns_client_cache.get_or_create(get_random_string(12), datetime(2929, 1, 1))
        self.assertIsNone(client)

    def test_apns_client_cache_same_topic_cached(self):
        push_certificate = force_push_certificate(with_material=True, reduced_key_size=False)
        client1 = apns_client_cache.get_or_create_with_push_cert(push_certificate)
        self.assertEqual(client1.not_after, push_certificate.not_after)
        client2 = apns_client_cache.get_or_create_with_push_cert(push_certificate)
        self.assertEqual(client1, client2)

    def test_apns_client_cache_same_topic_too_old(self):
        push_certificate = force_push_certificate(with_material=True, reduced_key_size=False)
        old_not_after = push_certificate.not_after
        client1 = apns_client_cache.get_or_create_with_push_cert(push_certificate)
        self.assertEqual(client1.not_after, old_not_after)
        # fake update
        push_certificate.not_after += timedelta(days=1)
        client2 = apns_client_cache.get_or_create_with_push_cert(push_certificate)
        self.assertNotEqual(client1, client2)
        self.assertEqual(client2.not_after, push_certificate.not_after)

    @patch("zentral.contrib.mdm.apns.logger.error")
    def test_apns_send_enrolled_device_notification_cannot_be_poked(self, logger_error):
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        session.enrolled_device.token = None
        send_enrolled_device_notification(session.enrolled_device)
        logger_error.assert_called_once_with("Enrolled %s %s cannot be poked.", "device", session.enrolled_device.pk)

    @patch("zentral.contrib.mdm.apns.logger.error")
    def test_apns_send_enrolled_user_notification_cannot_be_poked(self, logger_error):
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        session.enrolled_device.token = None
        enrolled_user = force_enrolled_user(session.enrolled_device)
        send_enrolled_user_notification(enrolled_user)
        logger_error.assert_called_once_with("Enrolled %s %s cannot be poked.", "user", enrolled_user.user_id)

    @patch("zentral.contrib.mdm.apns.time.sleep")
    @patch("zentral.contrib.mdm.apns.httpx.Client.post")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_apns_send_enrolled_device_notification_no_retries_failure(self, post_event, post, sleep):
        mocked_reponse = Mock()
        mocked_reponse.status_code = 400  # no retries if < 500
        post.return_value = mocked_reponse
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        success, _ = send_enrolled_device_notification(session.enrolled_device)
        self.assertFalse(success)
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
    def test_apns_send_enrolled_device_notification_retries_failure(self, post_event, post, sleep):
        mocked_reponse = Mock()
        mocked_reponse.status_code = 500  # retries if >= 500
        post.return_value = mocked_reponse
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        success, _ = send_enrolled_device_notification(session.enrolled_device)
        self.assertFalse(success)
        self.assertEqual(len(sleep.call_args), APNSClient.max_retries)
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MDMDeviceNotificationEvent)
        self.assertEqual(event.metadata.machine_serial_number, session.enrolled_device.serial_number)
        self.assertEqual(event.payload["status"], "failure")
        self.assertNotIn("user_id", event.payload)

    @patch("zentral.contrib.mdm.apns.time.sleep")
    @patch("zentral.contrib.mdm.apns.httpx.Client.post")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_apns_send_enrolled_device_notification_ok(self, post_event, post, sleep):
        mocked_reponse = Mock()
        mocked_reponse.status_code = 200
        post.return_value = mocked_reponse
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        success, _ = send_enrolled_device_notification(session.enrolled_device)
        self.assertTrue(success)
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
    def test_apns_send_enrolled_user_notification_no_retries_failure(self, post_event, post, sleep):
        mocked_reponse = Mock()
        mocked_reponse.status_code = 400  # no retries if < 500
        post.return_value = mocked_reponse
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        enrolled_user = force_enrolled_user(session.enrolled_device)
        success, _ = send_enrolled_user_notification(enrolled_user)
        self.assertFalse(success)
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
    def test_apns_send_enrolled_user_notification_retries_failure(self, post_event, post, sleep):
        mocked_reponse = Mock()
        mocked_reponse.status_code = 500  # retries if >= 500
        post.return_value = mocked_reponse
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        enrolled_user = force_enrolled_user(session.enrolled_device)
        success, _ = send_enrolled_user_notification(enrolled_user)
        self.assertFalse(success)
        self.assertEqual(len(sleep.call_args), APNSClient.max_retries)
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MDMDeviceNotificationEvent)
        self.assertEqual(event.metadata.machine_serial_number, session.enrolled_device.serial_number)
        self.assertEqual(event.payload["status"], "failure")
        self.assertEqual(event.payload["user_id"], enrolled_user.user_id)

    @patch("zentral.contrib.mdm.apns.time.sleep")
    @patch("zentral.contrib.mdm.apns.httpx.Client.post")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_apns_send_enrolled_user_notification_ok(self, post_event, post, sleep):
        mocked_reponse = Mock()
        mocked_reponse.status_code = 200
        post.return_value = mocked_reponse
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        enrolled_user = force_enrolled_user(session.enrolled_device)
        success, _ = send_enrolled_user_notification(enrolled_user)
        self.assertTrue(success)
        sleep.assert_not_called()
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MDMDeviceNotificationEvent)
        self.assertEqual(event.metadata.machine_serial_number, session.enrolled_device.serial_number)
        self.assertEqual(event.payload["status"], "success")
        self.assertEqual(event.payload["user_id"], enrolled_user.user_id)

from datetime import timedelta
from unittest.mock import patch, Mock
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.conf import ConfigDict
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.events import MDMDeviceNotificationEvent
from zentral.contrib.mdm.workers import get_workers, DevicesAPNSWorker, UsersAPNSWorker
from zentral.core.exceptions import ImproperlyConfigured
from .utils import force_dep_enrollment_session, force_enrolled_user, force_push_certificate


class MDMWorkersTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.push_certificate = force_push_certificate(with_material=True, reduced_key_size=False)
        cls.bad_push_certificate = force_push_certificate(with_material=False, reduced_key_size=False)
        cls.bad_push_certificate.certificate = None
        cls.bad_push_certificate.not_before = None
        cls.bad_push_certificate.not_after = None
        cls.bad_push_certificate.save()

    # common / config

    @patch("zentral.contrib.mdm.workers.settings")
    def test_bad_min_target_age_value_error(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"min_target_age": "A"}}
        })
        with self.assertRaises(ImproperlyConfigured, msg="APNS minimum target age must be an integer"):
            DevicesAPNSWorker()

    @patch("zentral.contrib.mdm.workers.settings")
    def test_bad_max_command_waiting_time_value_error(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"max_command_waiting_time": "A"}}
        })
        with self.assertRaises(ImproperlyConfigured, msg="APNS maximum command waiting time must be an integer"):
            DevicesAPNSWorker()

    @patch("zentral.contrib.mdm.workers.settings")
    def test_min_target_age_min(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"min_target_age": "0"}}
        })
        w = DevicesAPNSWorker()
        self.assertEqual(w.kwargs["min_target_age"], 1)

    @patch("zentral.contrib.mdm.workers.settings")
    def test_min_target_age_max(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"min_target_age": "3600"}}
        })
        w = DevicesAPNSWorker()
        self.assertEqual(w.kwargs["min_target_age"], 120)

    def test_min_target_age_default(self):
        w = DevicesAPNSWorker()
        self.assertEqual(w.kwargs["min_target_age"], 5)

    @patch("zentral.contrib.mdm.workers.settings")
    def test_batch_size_value_error(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"workers": {"batch_size": "A"}}}
        })
        with self.assertRaises(
            ImproperlyConfigured,
            msg="APNS workers batch size and visibility timeout must be integers"
        ):
            DevicesAPNSWorker()

    @patch("zentral.contrib.mdm.workers.settings")
    def test_batch_size_min(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"workers": {"batch_size": "0"}}}
        })
        w = DevicesAPNSWorker()
        self.assertEqual(w.kwargs["batch_size"], 1)

    @patch("zentral.contrib.mdm.workers.settings")
    def test_batch_size_max(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"workers": {"batch_size": "20000000"}}}
        })
        w = DevicesAPNSWorker()
        self.assertEqual(w.kwargs["batch_size"], 1000)

    def test_batch_size_default(self):
        w = DevicesAPNSWorker()
        self.assertEqual(w.kwargs["batch_size"], 50)

    @patch("zentral.contrib.mdm.workers.settings")
    def test_visibility_timeout_type_error(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"workers": {"visibility_timeout": None}}}
        })
        with self.assertRaises(
            ImproperlyConfigured,
            msg="APNS workers batch size and visibility timeout must be integers"
        ):
            DevicesAPNSWorker()

    @patch("zentral.contrib.mdm.workers.settings")
    def test_visibility_timeout_min(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"workers": {"visibility_timeout": 0}}}
        })
        w = DevicesAPNSWorker()
        self.assertEqual(w.kwargs["timeout"], 10)

    @patch("zentral.contrib.mdm.workers.settings")
    def test_visibility_timeout_max(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"workers": {"visibility_timeout": 131103}}}
        })
        w = DevicesAPNSWorker()
        self.assertEqual(w.kwargs["timeout"], 600)

    def test_visibility_timeout_default(self):
        w = DevicesAPNSWorker()
        self.assertEqual(w.kwargs["timeout"], 120)

    @patch("zentral.contrib.mdm.workers.settings")
    def test_default_period_value_error(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"connect": {"default_period": "A"}}}
        })
        with self.assertRaises(
            ImproperlyConfigured,
            msg="APNS connect values must be integers"
        ):
            DevicesAPNSWorker()

    @patch("zentral.contrib.mdm.workers.settings")
    def test_default_period_min(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"connect": {"default_period": "0"}}}
        })
        w = DevicesAPNSWorker()
        self.assertEqual(w.kwargs["default_period"], 60)

    @patch("zentral.contrib.mdm.workers.settings")
    def test_default_period_max(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"connect": {"default_period": "20000000"}}}
        })
        w = DevicesAPNSWorker()
        self.assertEqual(w.kwargs["default_period"], 604800)

    def test_default_period_default(self):
        w = DevicesAPNSWorker()
        self.assertEqual(w.kwargs["default_period"], 14400)

    @patch("zentral.contrib.mdm.workers.settings")
    def test_retry_delay_value_error(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"connect": {"retry_delay": "A"}}}
        })
        with self.assertRaises(
            ImproperlyConfigured,
            msg="APNS connect values must be integers"
        ):
            DevicesAPNSWorker()

    @patch("zentral.contrib.mdm.workers.settings")
    def test_retry_delay_min(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"connect": {"retry_delay": "0"}}}
        })
        w = DevicesAPNSWorker()
        self.assertEqual(w.kwargs["retry_delay"], 600)

    @patch("zentral.contrib.mdm.workers.settings")
    def test_retry_delay_max(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"connect": {"retry_delay": "20000000"}}}
        })
        w = DevicesAPNSWorker()
        self.assertEqual(w.kwargs["retry_delay"], 604800)

    def test_retry_delay_default(self):
        w = DevicesAPNSWorker()
        self.assertEqual(w.kwargs["retry_delay"], 86400)

    @patch("zentral.contrib.mdm.workers.settings")
    def test_enroll_retry_delay_value_error(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"connect": {"enroll_retry_delay": "A"}}}
        })
        with self.assertRaises(
            ImproperlyConfigured,
            msg="APNS connect values must be integers"
        ):
            DevicesAPNSWorker()

    @patch("zentral.contrib.mdm.workers.settings")
    def test_enroll_retry_delay_min(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"connect": {"enroll_retry_delay": "0"}}}
        })
        w = DevicesAPNSWorker()
        self.assertEqual(w.kwargs["enroll_retry_delay"], 10)

    @patch("zentral.contrib.mdm.workers.settings")
    def test_enroll_retry_delay_max(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"connect": {"enroll_retry_delay": "20000000"}}}
        })
        w = DevicesAPNSWorker()
        self.assertEqual(w.kwargs["enroll_retry_delay"], 3600)

    def test_enroll_retry_delay_default(self):
        w = DevicesAPNSWorker()
        self.assertEqual(w.kwargs["enroll_retry_delay"], 30)

    @patch("zentral.contrib.mdm.workers.settings")
    def test_capacity_value_error(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"workers": {"capacity": "A"}}}
        })
        with self.assertRaises(
            ImproperlyConfigured,
            msg="APNS workers capacity and rate must be floats"
        ):
            DevicesAPNSWorker()

    @patch("zentral.contrib.mdm.workers.settings")
    def test_capacity_min(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"workers": {"capacity": "0.1"}}}
        })
        w = DevicesAPNSWorker()
        self.assertEqual(w.notification_leaky_bucket.capacity, 1)

    @patch("zentral.contrib.mdm.workers.settings")
    def test_capacity_max(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"workers": {"capacity": "20000000"}}}
        })
        w = DevicesAPNSWorker()
        self.assertEqual(w.notification_leaky_bucket.capacity, 1000)

    def test_capacity_default(self):
        w = DevicesAPNSWorker()
        self.assertEqual(w.notification_leaky_bucket.capacity, 20)

    @patch("zentral.contrib.mdm.workers.settings")
    def test_rate_value_error(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"workers": {"rate": "A"}}}
        })
        with self.assertRaises(
            ImproperlyConfigured,
            msg="APNS workers capacity and rate must be floats"
        ):
            DevicesAPNSWorker()

    @patch("zentral.contrib.mdm.workers.settings")
    def test_rate_min(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"workers": {"rate": "0.01"}}}
        })
        w = DevicesAPNSWorker()
        self.assertEqual(w.notification_leaky_bucket.rate, 0.1)

    @patch("zentral.contrib.mdm.workers.settings")
    def test_rate_max(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.contrib.mdm": {"apns": {"workers": {"rate": "20000000"}}}
        })
        w = DevicesAPNSWorker()
        self.assertEqual(w.notification_leaky_bucket.rate, 1000)

    def test_rate_default(self):
        w = DevicesAPNSWorker()
        self.assertEqual(w.notification_leaky_bucket.rate, 10)

    def test_get_workers(self):
        workers = list(get_workers())
        self.assertIsInstance(workers[0], DevicesAPNSWorker)
        self.assertIsInstance(workers[1], UsersAPNSWorker)

    # device

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_devices_apns_worker_no_devices(self, post_event):
        w = DevicesAPNSWorker()
        w.run(only_once=True)
        self.assertEqual(len(post_event.call_args_list), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_devices_apns_worker_one_device_too_fresh_no_notifications(self, post_event):
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        enrolled_device = session.enrolled_device
        self.assertIsNone(enrolled_device.last_notified_at)
        w = DevicesAPNSWorker()
        w.run(only_once=True)
        self.assertEqual(len(post_event.call_args_list), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_devices_apns_worker_one_device_bad_push_certificate_no_notifications(self, post_event):
        self.assertIsNone(self.bad_push_certificate.certificate)
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.bad_push_certificate
        )
        enrolled_device = session.enrolled_device
        self.assertIsNone(enrolled_device.last_notified_at)
        enrolled_device.created_at -= timedelta(seconds=6)  # Old enough
        enrolled_device.save()
        w = DevicesAPNSWorker()
        w.run(only_once=True)
        self.assertEqual(len(post_event.call_args_list), 0)

    @patch("zentral.contrib.mdm.workers.apns_client_cache.get_or_create")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_devices_apns_worker_one_device_first_notification_success(self, post_event, get_or_create):
        client = Mock()
        client.send_notification.return_value = True
        get_or_create.return_value = client
        metrics_exporter = Mock()
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        enrolled_device = session.enrolled_device
        self.assertIsNone(enrolled_device.last_notified_at)
        enrolled_device.created_at -= timedelta(seconds=6)  # Old enough
        enrolled_device.save()
        w = DevicesAPNSWorker()
        w.run(metrics_exporter=metrics_exporter, only_once=True)
        enrolled_device.refresh_from_db()
        self.assertIsNotNone(enrolled_device.last_notified_at)
        self.assertIsNone(enrolled_device.notification_queued_at)
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MDMDeviceNotificationEvent)
        self.assertEqual(event.metadata.machine_serial_number, session.enrolled_device.serial_number)
        self.assertEqual(
            event.payload,
            {'apns_expiration_seconds': 86400,
             'apns_priority': 10,
             'status': 'success',
             'udid': enrolled_device.udid}
        )
        client.send_notification.assert_called_once_with(
            enrolled_device.token,
            enrolled_device.push_magic,
            priority=10,
            expiration_seconds=86400
        )
        metrics_exporter.start.assert_called_once()
        metrics_exporter.add_counter.assert_called_once_with(
            "apns_notification_sent",  ["target", "status"]
        )
        metrics_exporter.inc.assert_called_once_with(
            "apns_notification_sent", "device", "success"
        )

    @patch("zentral.contrib.mdm.workers.apns_client_cache.get_or_create")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_devices_apns_worker_one_device_first_notification_failure(self, post_event, get_or_create):
        client = Mock()
        client.send_notification.return_value = False
        get_or_create.return_value = client
        metrics_exporter = Mock()
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        enrolled_device = session.enrolled_device
        self.assertIsNone(enrolled_device.last_notified_at)
        enrolled_device.created_at -= timedelta(seconds=6)  # Old enough
        enrolled_device.save()
        w = DevicesAPNSWorker()
        w.run(metrics_exporter=metrics_exporter, only_once=True)
        enrolled_device.refresh_from_db()
        self.assertIsNone(enrolled_device.last_notified_at)
        self.assertIsNone(enrolled_device.notification_queued_at)
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MDMDeviceNotificationEvent)
        self.assertEqual(event.metadata.machine_serial_number, session.enrolled_device.serial_number)
        self.assertEqual(
            event.payload,
            {'apns_expiration_seconds': 86400,
             'apns_priority': 10,
             'status': 'failure',
             'udid': enrolled_device.udid}
        )
        client.send_notification.assert_called_once_with(
            enrolled_device.token,
            enrolled_device.push_magic,
            priority=10,
            expiration_seconds=86400
        )
        metrics_exporter.start.assert_called_once()
        metrics_exporter.add_counter.assert_called_once_with(
            "apns_notification_sent",  ["target", "status"]
        )
        metrics_exporter.inc.assert_called_once_with(
            "apns_notification_sent", "device", "failure"
        )

    @patch("zentral.contrib.mdm.workers.apns_client_cache.get_or_create")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_devices_apns_worker_one_device_second_notification_failure(self, post_event, get_or_create):
        client = Mock()
        client.send_notification.return_value = False
        get_or_create.return_value = client
        metrics_exporter = Mock()
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        enrolled_device = session.enrolled_device
        self.assertIsNone(enrolled_device.last_notified_at)
        enrolled_device.created_at -= timedelta(days=6)  # Old enough
        enrolled_device.last_notified_at = last_notified_at = enrolled_device.created_at + timedelta(days=1)
        enrolled_device.save()
        w = DevicesAPNSWorker()
        w.run(metrics_exporter=metrics_exporter, only_once=True)
        enrolled_device.refresh_from_db()
        self.assertEqual(enrolled_device.last_notified_at, last_notified_at)  # Not updated
        self.assertIsNone(enrolled_device.notification_queued_at)
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MDMDeviceNotificationEvent)
        self.assertEqual(event.metadata.machine_serial_number, session.enrolled_device.serial_number)
        self.assertEqual(
            event.payload,
            {'apns_expiration_seconds': 86400,
             'apns_priority': 10,
             'status': 'failure',
             'udid': enrolled_device.udid}
        )
        client.send_notification.assert_called_once_with(
            enrolled_device.token,
            enrolled_device.push_magic,
            priority=10,
            expiration_seconds=86400
        )
        metrics_exporter.start.assert_called_once()
        metrics_exporter.add_counter.assert_called_once_with(
            "apns_notification_sent",  ["target", "status"]
        )
        metrics_exporter.inc.assert_called_once_with(
            "apns_notification_sent", "device", "failure"
        )

    @patch("zentral.contrib.mdm.workers.apns_client_cache.get_or_create")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_devices_apns_worker_one_device_no_client(self, post_event, get_or_create):
        get_or_create.return_value = None
        metrics_exporter = Mock()
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        enrolled_device = session.enrolled_device
        self.assertIsNone(enrolled_device.last_notified_at)
        enrolled_device.created_at -= timedelta(seconds=6)  # Old enough
        enrolled_device.save()
        w = DevicesAPNSWorker()
        w.run(metrics_exporter=metrics_exporter, only_once=True)
        enrolled_device.refresh_from_db()
        self.assertIsNone(enrolled_device.last_notified_at)
        self.assertIsNone(enrolled_device.notification_queued_at)
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MDMDeviceNotificationEvent)
        self.assertEqual(event.metadata.machine_serial_number, session.enrolled_device.serial_number)
        self.assertEqual(
            event.payload,
            {'apns_expiration_seconds': 86400,
             'apns_priority': 10,
             'status': 'failure',
             'udid': enrolled_device.udid}
        )
        metrics_exporter.start.assert_called_once()
        metrics_exporter.add_counter.assert_called_once_with(
            "apns_notification_sent",  ["target", "status"]
        )
        metrics_exporter.inc.assert_called_once_with(
            "apns_notification_sent", "device", "no_client"
        )

    # user

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_users_apns_worker_no_users(self, post_event):
        w = UsersAPNSWorker()
        w.run(only_once=True)
        self.assertEqual(len(post_event.call_args_list), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_users_apns_worker_one_user_too_fresh_no_notifications(self, post_event):
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        enrolled_user = force_enrolled_user(session.enrolled_device)
        self.assertIsNone(enrolled_user.last_notified_at)
        w = UsersAPNSWorker()
        w.run(only_once=True)
        self.assertEqual(len(post_event.call_args_list), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_users_apns_worker_one_user_bad_push_certificate_no_notifications(self, post_event):
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.bad_push_certificate
        )
        enrolled_user = force_enrolled_user(session.enrolled_device)
        self.assertIsNone(enrolled_user.last_notified_at)
        enrolled_user.created_at -= timedelta(seconds=6)  # Old enough
        enrolled_user.save()
        w = UsersAPNSWorker()
        w.run(only_once=True)
        self.assertEqual(len(post_event.call_args_list), 0)

    @patch("zentral.contrib.mdm.workers.apns_client_cache.get_or_create")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_users_apns_worker_one_user_first_notification_success(self, post_event, get_or_create):
        client = Mock()
        client.send_notification.return_value = True
        get_or_create.return_value = client
        metrics_exporter = Mock()
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        enrolled_device = session.enrolled_device
        enrolled_user = force_enrolled_user(enrolled_device)
        self.assertIsNone(enrolled_user.last_notified_at)
        enrolled_user.created_at -= timedelta(seconds=6)  # Old enough
        enrolled_user.save()
        w = UsersAPNSWorker()
        w.run(metrics_exporter=metrics_exporter, only_once=True)
        enrolled_user.refresh_from_db()
        self.assertIsNotNone(enrolled_user.last_notified_at)
        self.assertIsNone(enrolled_user.notification_queued_at)
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MDMDeviceNotificationEvent)
        self.assertEqual(event.metadata.machine_serial_number, enrolled_device.serial_number)
        self.assertEqual(
            event.payload,
            {'apns_expiration_seconds': 86400,
             'apns_priority': 10,
             'status': 'success',
             'udid': enrolled_device.udid,
             'user_id': enrolled_user.user_id}
        )
        client.send_notification.assert_called_once_with(
            enrolled_user.token,
            enrolled_device.push_magic,
            priority=10,
            expiration_seconds=86400
        )
        metrics_exporter.start.assert_called_once()
        metrics_exporter.add_counter.assert_called_once_with(
            "apns_notification_sent",  ["target", "status"]
        )
        metrics_exporter.inc.assert_called_once_with(
            "apns_notification_sent", "user", "success"
        )

    @patch("zentral.contrib.mdm.workers.apns_client_cache.get_or_create")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_users_apns_worker_one_user_first_notification_failure(self, post_event, get_or_create):
        client = Mock()
        client.send_notification.return_value = False
        get_or_create.return_value = client
        metrics_exporter = Mock()
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        enrolled_device = session.enrolled_device
        enrolled_user = force_enrolled_user(enrolled_device)
        self.assertIsNone(enrolled_user.last_notified_at)
        enrolled_user.created_at -= timedelta(seconds=6)  # Old enough
        enrolled_user.save()
        w = UsersAPNSWorker()
        w.run(metrics_exporter=metrics_exporter, only_once=True)
        enrolled_user.refresh_from_db()
        self.assertIsNone(enrolled_user.last_notified_at)
        self.assertIsNone(enrolled_user.notification_queued_at)
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MDMDeviceNotificationEvent)
        self.assertEqual(event.metadata.machine_serial_number, enrolled_device.serial_number)
        self.assertEqual(
            event.payload,
            {'apns_expiration_seconds': 86400,
             'apns_priority': 10,
             'status': 'failure',
             'udid': enrolled_device.udid,
             'user_id': enrolled_user.user_id}
        )
        client.send_notification.assert_called_once_with(
            enrolled_user.token,
            enrolled_device.push_magic,
            priority=10,
            expiration_seconds=86400
        )
        metrics_exporter.start.assert_called_once()
        metrics_exporter.add_counter.assert_called_once_with(
            "apns_notification_sent",  ["target", "status"]
        )
        metrics_exporter.inc.assert_called_once_with(
            "apns_notification_sent", "user", "failure"
        )

    @patch("zentral.contrib.mdm.workers.apns_client_cache.get_or_create")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_users_apns_worker_one_user_second_notification_failure(self, post_event, get_or_create):
        client = Mock()
        client.send_notification.return_value = False
        get_or_create.return_value = client
        metrics_exporter = Mock()
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        enrolled_device = session.enrolled_device
        enrolled_user = force_enrolled_user(enrolled_device)
        self.assertIsNone(enrolled_user.last_notified_at)
        enrolled_user.created_at -= timedelta(days=6)  # Old enough
        enrolled_user.last_notified_at = last_notified_at = enrolled_user.created_at + timedelta(days=1)
        enrolled_user.save()
        w = UsersAPNSWorker()
        w.run(metrics_exporter=metrics_exporter, only_once=True)
        enrolled_user.refresh_from_db()
        self.assertEqual(enrolled_user.last_notified_at, last_notified_at)  # Not updated
        self.assertIsNone(enrolled_user.notification_queued_at)
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MDMDeviceNotificationEvent)
        self.assertEqual(event.metadata.machine_serial_number, enrolled_device.serial_number)
        self.assertEqual(
            event.payload,
            {'apns_expiration_seconds': 86400,
             'apns_priority': 10,
             'status': 'failure',
             'udid': enrolled_device.udid,
             'user_id': enrolled_user.user_id}
        )
        client.send_notification.assert_called_once_with(
            enrolled_user.token,
            enrolled_device.push_magic,
            priority=10,
            expiration_seconds=86400
        )
        metrics_exporter.start.assert_called_once()
        metrics_exporter.add_counter.assert_called_once_with(
            "apns_notification_sent",  ["target", "status"]
        )
        metrics_exporter.inc.assert_called_once_with(
            "apns_notification_sent", "user", "failure"
        )

    @patch("zentral.contrib.mdm.workers.apns_client_cache.get_or_create")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_users_apns_worker_one_user_no_client(self, post_event, get_or_create):
        get_or_create.return_value = None
        metrics_exporter = Mock()
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True, push_certificate=self.push_certificate
        )
        enrolled_device = session.enrolled_device
        enrolled_user = force_enrolled_user(enrolled_device)
        self.assertIsNone(enrolled_user.last_notified_at)
        enrolled_user.created_at -= timedelta(seconds=6)  # Old enough
        enrolled_user.save()
        w = UsersAPNSWorker()
        w.run(metrics_exporter=metrics_exporter, only_once=True)
        enrolled_user.refresh_from_db()
        self.assertIsNone(enrolled_user.last_notified_at)
        self.assertIsNone(enrolled_user.notification_queued_at)
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MDMDeviceNotificationEvent)
        self.assertEqual(event.metadata.machine_serial_number, enrolled_device.serial_number)
        self.assertEqual(
            event.payload,
            {'apns_expiration_seconds': 86400,
             'apns_priority': 10,
             'status': 'failure',
             'udid': enrolled_device.udid,
             'user_id': enrolled_user.user_id}
        )
        metrics_exporter.start.assert_called_once()
        metrics_exporter.add_counter.assert_called_once_with(
            "apns_notification_sent",  ["target", "status"]
        )
        metrics_exporter.inc.assert_called_once_with(
            "apns_notification_sent", "user", "no_client"
        )

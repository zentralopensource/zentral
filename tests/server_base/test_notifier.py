from django.test import SimpleTestCase
from base.notifier import Notifier


class TestNotifierKwargs(SimpleTestCase):
    maxDiff = None

    def test_default_url(self):
        notifier = Notifier(None)
        self.assertEqual(notifier._kwargs["host"], "redis")
        self.assertEqual(notifier._kwargs["port"], 6379)
        self.assertEqual(notifier._kwargs["db"], 15)
        self.assertFalse(notifier._kwargs["ssl"])

    def test_url_without_path(self):
        notifier = Notifier({"url": "redis://redis:6379"})
        self.assertEqual(notifier._kwargs["db"], 0)

    def test_bad_path(self):
        with self.assertRaises(ValueError) as cm:
            Notifier({"url": "redis://redis:6379/yolo"})
        self.assertEqual(cm.exception.args[0], "Could not parse path")

    def test_tls_scheme(self):
        notifier = Notifier({"url": "rediss://redis:6379/15"})
        self.assertTrue(notifier._kwargs["ssl"])

    def test_credentials(self):
        notifier = Notifier({"url": "redis://redis:6379/15", "username": "un", "password": "pwd"})
        self.assertEqual(notifier._kwargs["username"], "un")
        self.assertEqual(notifier._kwargs["password"], "pwd")

    def test_socket_timeouts(self):
        notifier = Notifier(None)
        self.assertEqual(notifier._kwargs["socket_connect_timeout"], 3.0)
        self.assertEqual(notifier._kwargs["socket_timeout"], 3.0)

    def test_health_check_interval(self):
        notifier = Notifier(None)
        self.assertEqual(notifier._kwargs["health_check_interval"], 30)

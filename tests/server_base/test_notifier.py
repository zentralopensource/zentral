import gc
import weakref
from unittest.mock import call, patch, Mock
from django.test import SimpleTestCase
from base.notifier import build_notifier, Notifier


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


class CallbackHolder:
    def __init__(self):
        self.calls = []

    def callback(self, data):
        self.calls.append(data)


class TestNotifier(SimpleTestCase):
    maxDiff = None

    def build_notifier(self):
        notifier = Notifier(None)
        patcher = patch("base.notifier.redis")
        redis = patcher.start()
        self.addCleanup(patcher.stop)
        return notifier, redis

    # _get_client / _get_pubsub

    def test_get_client_is_built_once(self):
        notifier, redis = self.build_notifier()
        self.assertIs(notifier._get_client(), notifier._get_client())
        redis.Redis.assert_called_once_with(**notifier._kwargs)

    def test_get_pubsub_is_built_once(self):
        notifier, redis = self.build_notifier()
        self.assertIs(notifier._get_pubsub(), notifier._get_pubsub())
        redis.Redis.return_value.pubsub.assert_called_once_with(ignore_subscribe_messages=True)

    # _subscribe

    def test_subscribe_starts_the_thread_once(self):
        notifier, redis = self.build_notifier()
        pubsub = redis.Redis.return_value.pubsub.return_value
        notifier._subscribe("yolo")
        pubsub.subscribe.assert_called_once_with(yolo=notifier._message_handler)
        self.assertIs(notifier._thread, pubsub.run_in_thread.return_value)
        notifier._subscribe("fomo")
        pubsub.run_in_thread.assert_called_once()
        self.assertEqual(pubsub.subscribe.call_args_list[-1], call(fomo=notifier._message_handler))

    # _message_handler

    def test_message_handler_unknown_channel(self):
        notifier, _ = self.build_notifier()
        with self.assertLogs("server.base.notifier", level="ERROR") as cm:
            notifier._message_handler({"channel": "yolo", "data": "fomo"})
        self.assertIn("ERROR:server.base.notifier:Unknown channel: yolo", cm.output)

    def test_message_handler_plain_callback(self):
        notifier, _ = self.build_notifier()
        holder = CallbackHolder()
        notifier._callbacks["yolo"] = [holder.callback]
        notifier._message_handler({"channel": "yolo", "data": "fomo"})
        self.assertEqual(holder.calls, ["fomo"])

    def test_message_handler_live_weakref_callback(self):
        notifier, _ = self.build_notifier()
        holder = CallbackHolder()
        notifier._callbacks["yolo"] = [weakref.WeakMethod(holder.callback)]
        notifier._message_handler({"channel": "yolo", "data": "fomo"})
        self.assertEqual(holder.calls, ["fomo"])
        self.assertEqual(len(notifier._callbacks["yolo"]), 1)

    def test_message_handler_removes_dead_weakref_callback(self):
        notifier, _ = self.build_notifier()
        holder = CallbackHolder()
        notifier._callbacks["yolo"] = [weakref.WeakMethod(holder.callback)]
        del holder
        gc.collect()
        notifier._message_handler({"channel": "yolo", "data": "fomo"})
        self.assertEqual(notifier._callbacks["yolo"], [])

    # _schedule_reconnect

    def test_schedule_reconnect_starts_a_timer(self):
        notifier, _ = self.build_notifier()
        with patch("base.notifier.threading.Timer") as timer:
            notifier._schedule_reconnect()
            timer.assert_called_once()
            timer.return_value.start.assert_called_once()
        self.assertIs(notifier._reconnect_timer, timer.return_value)

    def test_schedule_reconnect_keeps_the_current_timer(self):
        notifier, _ = self.build_notifier()
        current_timer = Mock()
        notifier._reconnect_timer = current_timer
        with patch("base.notifier.threading.Timer") as timer:
            notifier._schedule_reconnect()
            timer.assert_not_called()
        self.assertIs(notifier._reconnect_timer, current_timer)

    def test_schedule_reconnect_forced_replaces_the_current_timer(self):
        notifier, _ = self.build_notifier()
        notifier._reconnect_timer = Mock()
        with patch("base.notifier.threading.Timer") as timer:
            notifier._schedule_reconnect(force=True)
            timer.assert_called_once()
        self.assertIs(notifier._reconnect_timer, timer.return_value)

    # _reconnect

    def test_reconnect(self):
        notifier, redis = self.build_notifier()
        notifier._callbacks["yolo"] = [Mock()]
        pubsub = redis.Redis.return_value.pubsub.return_value
        notifier._pubsub = pubsub
        notifier._reconnect_timer = Mock()
        with self.assertLogs("server.base.notifier", level="INFO") as cm:
            notifier._reconnect()
        pubsub.close.assert_called_once()
        pubsub.subscribe.assert_called_once_with(yolo=notifier._message_handler)
        self.assertIsNone(notifier._reconnect_timer)
        self.assertIn("INFO:server.base.notifier:Reconnected", cm.output)

    def test_reconnect_without_pubsub(self):
        notifier, redis = self.build_notifier()
        notifier._reconnect()
        redis.Redis.return_value.pubsub.return_value.close.assert_not_called()

    def test_reconnect_error_is_rescheduled(self):
        notifier, redis = self.build_notifier()
        notifier._callbacks["yolo"] = [Mock()]
        pubsub = redis.Redis.return_value.pubsub.return_value
        notifier._pubsub = pubsub
        pubsub.subscribe.side_effect = Exception("boom")
        with patch("base.notifier.threading.Timer") as timer:
            with self.assertLogs("server.base.notifier", level="ERROR") as cm:
                notifier._reconnect()
            timer.assert_called_once()
        self.assertIn("ERROR:server.base.notifier:Could not reconnect: boom", cm.output)

    # _exception_handler

    def test_exception_handler_stops_the_thread(self):
        notifier, _ = self.build_notifier()
        thread = Mock()
        notifier._thread = thread
        with patch("base.notifier.threading.Timer"):
            with self.assertLogs("server.base.notifier", level="ERROR") as cm:
                notifier._exception_handler(Exception("boom"), Mock(), thread)
        thread.stop.assert_called_once()
        thread.join.assert_called_once_with(timeout=1.0)
        self.assertIsNone(notifier._thread)
        self.assertIn("ERROR:server.base.notifier:Exception: boom", cm.output)

    def test_exception_handler_thread_cannot_be_joined(self):
        notifier, _ = self.build_notifier()
        thread = Mock()
        thread.join.side_effect = RuntimeError
        notifier._thread = thread
        with patch("base.notifier.threading.Timer"):
            with self.assertLogs("server.base.notifier", level="ERROR") as cm:
                notifier._exception_handler(Exception("boom"), Mock(), thread)
        self.assertIn("ERROR:server.base.notifier:Cannot join stopping thread", cm.output)
        self.assertIsNone(notifier._thread)

    def test_exception_handler_without_thread(self):
        notifier, _ = self.build_notifier()
        with patch("base.notifier.threading.Timer") as timer:
            with self.assertLogs("server.base.notifier", level="ERROR"):
                notifier._exception_handler(Exception("boom"), Mock(), Mock())
            timer.assert_called_once()

    # add_callback

    def test_add_callback_subscribes_the_first_time_only(self):
        notifier, redis = self.build_notifier()
        pubsub = redis.Redis.return_value.pubsub.return_value
        notifier.add_callback("yolo", Mock())
        pubsub.subscribe.assert_called_once_with(yolo=notifier._message_handler)
        notifier.add_callback("yolo", Mock())
        pubsub.subscribe.assert_called_once()
        self.assertEqual(len(notifier._callbacks["yolo"]), 2)

    def test_add_callback_subscribe_error_is_rescheduled(self):
        notifier, redis = self.build_notifier()
        pubsub = redis.Redis.return_value.pubsub.return_value
        pubsub.subscribe.side_effect = Exception("boom")
        with patch("base.notifier.threading.Timer") as timer:
            with self.assertLogs("server.base.notifier", level="ERROR") as cm:
                notifier.add_callback("yolo", Mock())
            timer.assert_called_once()
        self.assertIn("ERROR:server.base.notifier:Could not subscribe to channel yolo: boom", cm.output)
        # the callback is kept, the reconnection subscribes again
        self.assertEqual(len(notifier._callbacks["yolo"]), 1)

    # send_notification

    def test_send_notification(self):
        notifier, redis = self.build_notifier()
        notifier.send_notification("yolo", "fomo")
        redis.Redis.return_value.publish.assert_called_once_with("yolo", "fomo")

    def test_send_notification_error_is_logged(self):
        notifier, redis = self.build_notifier()
        redis.Redis.return_value.publish.side_effect = Exception("boom")
        with self.assertLogs("server.base.notifier", level="ERROR") as cm:
            notifier.send_notification("yolo")
        self.assertIn("Could not send notification on channel yolo", "\n".join(cm.output))

    # build_notifier

    def test_build_notifier(self):
        self.assertIsInstance(build_notifier(), Notifier)

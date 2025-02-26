import logging
import random
import threading
from urllib.parse import urlparse
import weakref
from zentral.conf import settings
from django.utils.functional import SimpleLazyObject
import redis


logger = logging.getLogger("server.base.notifier")


class Notifier:
    _reconnection_delay_range = (1.0, 3.0)

    def __init__(self, config):
        self._client = None
        self._pubsub = None
        self._thread = None
        self._reconnect_timer = None
        self._callbacks = {}
        self._lock = threading.Lock()
        self._build_kwargs(config)

    def _build_kwargs(self, config):
        config = config or {}
        url = config.get("url")
        if not url:
            url = "redis://redis:6379/15"
        parsed_url = urlparse(url)
        if parsed_url.path:
            try:
                db = int(parsed_url.path.lstrip("/"))
            except Exception:
                raise ValueError("Could not parse path")
        else:
            db = 0
        self._kwargs = {
            "host": parsed_url.hostname,
            "port": parsed_url.port,
            "db": db,
            "ssl": parsed_url.scheme == "rediss",
            "username": config.get("username"),
            "password": config.get("password"),
            "decode_responses": True,
        }

    def _get_client(self):
        if self._client is None:
            self._client = redis.Redis(**self._kwargs)
        return self._client

    def _get_pubsub(self):
        if self._pubsub is None:
            self._pubsub = self._get_client().pubsub(ignore_subscribe_messages=True)
        return self._pubsub

    def _subscribe(self, *channels):
        p = self._get_pubsub()
        p.subscribe(**{channel: self._message_handler for channel in channels})
        if self._thread is None:
            logger.debug("Start thread")
            self._thread = p.run_in_thread(
                exception_handler=self._exception_handler,
                daemon=True,
                # sleep_time is a bad name for this important parameter.
                # see https://github.com/redis/redis-py/issues/821
                # with 60s, problems with the socket will be recovered from,
                # and we let the OS do its job.
                sleep_time=60.0
            )

    def _message_handler(self, message):
        channel = message['channel']
        data = message['data']
        logger.info("Received notification on channel %s", channel)
        callbacks = self._callbacks.get(channel)
        if not callbacks:
            logger.error("Unknown channel: %s", channel)
            return
        dead_weakrefs = []
        for callback in callbacks:
            logger.debug("Calling callback %s for channel %s", callback, channel)
            if isinstance(callback, weakref.ref):
                func = callback()
                if func is None:
                    logger.debug("Callback %s is a dead weakref for channel %s", callback, channel)
                    dead_weakrefs.append(callback)
                    continue
            else:
                func = callback
            func(data)
        if dead_weakrefs:
            with self._lock:
                for dead_weakref in dead_weakrefs:
                    logger.debug("Remove dead weakref callback %s for channel %s", dead_weakref, channel)
                    callbacks.remove(dead_weakref)

    def _reconnect(self):
        logger.info("Reconnect")
        with self._lock:
            if self._pubsub:
                self._pubsub.close()
            try:
                self._subscribe(*self._callbacks.keys())
            except Exception as ex:
                logger.error("Could not reconnect: %s", ex)
                self._schedule_reconnect(force=True)
            else:
                self._reconnect_timer = None
                logger.info("Reconnected")

    def _schedule_reconnect(self, force=False):
        logger.debug("Schedule reconnect")
        if self._reconnect_timer is None or force:
            reconnection_delay = random.uniform(*self._reconnection_delay_range)
            logger.info("Try to reconnect in %0.1fs", reconnection_delay)
            self._reconnect_timer = threading.Timer(reconnection_delay, self._reconnect)
            self._reconnect_timer.start()

    def _exception_handler(self, ex, pubsub, thread):
        logger.error("Exception: %s", ex)
        if self._thread is not None:
            self._thread.stop()
            try:
                self._thread.join(timeout=1.0)
            except RuntimeError:
                logger.error("Cannot join stopping thread")
            with self._lock:
                self._thread = None
        self._schedule_reconnect()

    # public interface

    def add_callback(self, channel, callback):
        with self._lock:
            channel_callbacks = self._callbacks.setdefault(channel, [])
            if not channel_callbacks:
                try:
                    self._subscribe(channel)
                except Exception as ex:
                    logger.error("Could not subscribe to channel %s: %s", channel, ex)
                    self._schedule_reconnect()
            channel_callbacks.append(callback)

    def send_notification(self, channel, data=""):
        try:
            self._get_client().publish(channel, data)
        except Exception:
            logger.exception("Could not send notification on channel %s", channel)


def build_notifier():
    return Notifier(settings.get("notifier"))


notifier = SimpleLazyObject(build_notifier)

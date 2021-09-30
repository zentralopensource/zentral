import logging
import queue
import random
import threading
import time
from django.utils.functional import cached_property
import requests
from zentral.core.stores.backends.base import BaseEventStore


logger = logging.getLogger('zentral.core.stores.backends.http')


class HTTPStoreClient:
    max_retries = 3

    def __init__(self, event_store, name="client"):
        self.endpoint_url = event_store.endpoint_url
        self.session = requests.Session()
        self.session.verify = event_store.verify_tls
        self.session.headers.update({'Content-Type': 'application/json'})
        if event_store.headers:
            self.session.headers.update(event_store.headers)
        if event_store.username and event_store.password:
            self.session.auth = (event_store.username, event_store.password)
        self.name = name

    def _serialize_event(self, event):
        if not isinstance(event, dict):
            event = event.serialize()
        payload = event.pop("_zentral")
        event_type = payload.get("type")
        namespace = payload.get("namespace", event_type)
        payload[namespace] = event
        return payload

    def store_event(self, event):
        payload = self._serialize_event(event)
        for i in range(self.max_retries):
            r = self.session.post(self.endpoint_url, json=payload)
            if r.ok:
                return
            if r.status_code > 500:
                logger.error("[%s] temporary server error", self.name)
                if i + 1 < self.max_retries:
                    seconds = random.uniform(3, 4) * (i + 1)
                    logger.error("[%s] retry in %.1fs", self.name, seconds)
                    time.sleep(seconds)
                    continue
            r.raise_for_status()


class EventStoreThread(threading.Thread):
    def __init__(self, event_store, thread_id, in_queue, out_queue, stop_event):
        name = f"HTTP store thread {thread_id}"
        logger.debug("[%s] initialize", name)
        self.client = HTTPStoreClient(event_store, name)
        self.in_queue = in_queue
        self.out_queue = out_queue
        self.stop_event = stop_event
        super().__init__(name=name)

    def run(self):
        logger.info("[%s] start", self.name)
        while True:
            try:
                receipt_handle, routing_key, event_d = self.in_queue.get(block=True, timeout=1)
            except queue.Empty:
                logger.debug("[%s] no event to store", self.name)
                if self.stop_event.is_set():
                    logger.info("[%s] graceful exit", self.name)
                    break
            else:
                event_type = event_d['_zentral']['type']
                logger.debug("[%s] new %s event to store", self.name, event_type)
                request_time = time.monotonic()
                try:
                    self.client.store_event(event_d)
                except Exception:
                    logger.exception("[%s] could not store event", self.name)
                    self.out_queue.put((receipt_handle, False, event_type, time.monotonic() - request_time))
                else:
                    self.out_queue.put((receipt_handle, True, event_type, time.monotonic() - request_time))


class EventStore(BaseEventStore):
    max_retries = 3
    max_concurrency = 20

    def __init__(self, config_d):
        super().__init__(config_d)
        self.endpoint_url = config_d["endpoint_url"]
        self.verify_tls = config_d.get('verify_tls', True)
        self.headers = config_d.get("headers")
        self.username = config_d.get("username")
        self.password = config_d.get("password")
        if self.username and not self.password:
            logger.error("Username set without password")
        elif self.password and not self.username:
            logger.error("Password set without username")
        elif self.headers and self.password and self.username and "AUTHORIZATION" in (k.upper() for k in self.headers):
            logger.error("Basic auth AND Authorization header cannot be both configured")

    def get_process_thread_constructor(self):
        def constructor(thread_id, in_queue, out_queue, stop_event):
            return EventStoreThread(self, thread_id, in_queue, out_queue, stop_event)
        return constructor

    @cached_property
    def client(self):
        return HTTPStoreClient(self)

    def store(self, event):
        self.client.store_event(event)

import logging
import queue
import threading
import time
from urllib.parse import urlparse
from django.utils.functional import cached_property
from kombu.utils import json
import requests
from rest_framework import serializers
from .base import BaseStore
from base.utils import deployment_info
from zentral.utils.requests import CustomHTTPAdapter


logger = logging.getLogger('zentral.core.stores.backends.http')


class HTTPStoreClient:
    default_request_timeout = 120
    max_request_timeout = 600
    default_max_retries = 3
    max_max_retries = 5

    def __init__(self, store, name="client"):
        self.endpoint_url = store.endpoint_url
        self.name = name
        # Session
        self.session = requests.Session()
        self.session.verify = store.verify_tls
        self.session.headers.update({'Content-Type': 'application/json',
                                     'User-Agent': deployment_info.user_agent})
        if store.headers:
            self.session.headers.update({h["name"]: h["value"] for h in store.headers})
        if store.username and store.password:
            self.session.auth = (store.username, store.password)
        self.session.mount(self.endpoint_url, CustomHTTPAdapter(store.request_timeout, store.max_retries))

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
        r = self.session.post(self.endpoint_url, data=json.dumps(payload))
        r.raise_for_status()


class HTTPStoreThread(threading.Thread):
    def __init__(self, store, thread_id, in_queue, out_queue, stop_event):
        name = f"HTTP store thread {thread_id}"
        logger.debug("[%s] initialize", name)
        self.client = HTTPStoreClient(store, name)
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


class HTTPStore(BaseStore):
    kwargs_keys = (
        "endpoint_url",
        "verify_tls",
        "username",
        "password",
        "headers",
        "concurrency",
        "max_retries",
        "request_timeout"
    )
    encrypted_kwargs_paths = (
        ["headers", "*", "value"],
        ["password"],
    )
    max_concurrency = 20

    def get_process_thread_constructor(self):
        def constructor(thread_id, in_queue, out_queue, stop_event):
            return HTTPStoreThread(self, thread_id, in_queue, out_queue, stop_event)
        return constructor

    @cached_property
    def client(self):
        return HTTPStoreClient(self)

    def store(self, event):
        self.client.store_event(event)


# Serializers


class HTTPURLField(serializers.Field):
    def to_representation(self, value):
        return str(value)

    def to_internal_value(self, data):
        if not isinstance(data, str):
            raise serializers.ValidationError("Incorrect type")
        pr = urlparse(data)
        if pr.scheme not in ("http", "https"):
            raise serializers.ValidationError("Invalid URL scheme")
        if not pr.netloc:
            raise serializers.ValidationError("Invalid URL netloc")
        return data


class HTTPHeaderSerializer(serializers.Serializer):
    name = serializers.CharField()
    value = serializers.CharField()


class HTTPStoreSerializer(serializers.Serializer):
    endpoint_url = HTTPURLField()
    verify_tls = serializers.BooleanField(required=False, default=True)
    username = serializers.CharField(required=False, allow_null=True)
    password = serializers.CharField(required=False, allow_null=True)
    headers = HTTPHeaderSerializer(many=True, required=False)
    concurrency = serializers.IntegerField(max_value=HTTPStore.max_concurrency, min_value=1, default=1)
    request_timeout = serializers.IntegerField(
        min_value=1,
        max_value=HTTPStoreClient.max_request_timeout,
        default=HTTPStoreClient.default_request_timeout,
    )
    max_retries = serializers.IntegerField(
        min_value=1,
        max_value=HTTPStoreClient.max_max_retries,
        default=HTTPStoreClient.default_max_retries,
    )

    def validate(self, data):
        username = data.get("username")
        password = data.get("password")
        if username and not password:
            raise serializers.ValidationError({"password": "Required when username is set"})
        elif password and not username:
            raise serializers.ValidationError({"username": "Required when password is set"})
        if username and any(h["name"].upper() == "AUTHORIZATION" for h in data.get("headers", [])):
            raise serializers.ValidationError("Basic Auth and Authorization header cannot be both set")
        return data

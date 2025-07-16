import gzip
from kombu.utils import json
import requests
from rest_framework import serializers
from base.utils import deployment_info
from zentral.core.stores.backends.base import BaseStore
from zentral.utils.requests import CustomHTTPAdapter


class PantherStore(BaseStore):
    kwargs_keys = (
        "endpoint_url",
        "bearer_token",
        "batch_size",
    )
    encrypted_kwargs_paths = (
        ["bearer_token"],
    )
    max_batch_size = 100
    request_timeout = 300
    max_retries = 3

    def load(self):
        super().load()
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {self.bearer_token}',
            'Content-Encoding': 'gzip',
            'User-Agent': deployment_info.user_agent,
        })
        self.session.mount(self.endpoint_url, CustomHTTPAdapter(self.request_timeout, self.max_retries))

    def _serialize_event(self, event):
        if not isinstance(event, dict):
            event_d = event.serialize()
        else:
            event_d = event
        p_event_d = event_d.pop("_zentral")
        p_event_d["payload"] = event_d
        return p_event_d

    def store(self, event):
        p_event_d = self._serialize_event(event)
        data = gzip.compress(json.dumps(p_event_d).encode("utf-8"))
        response = self.session.post(self.endpoint_url, data=data)
        response.raise_for_status()

    def bulk_store(self, events):
        if self.batch_size < 2:
            raise RuntimeError("bulk_store is not available when batch_size < 2")
        event_keys = []
        payload = b""
        for event in events:
            serialized_event = self._serialize_event(event)
            event_keys.append((serialized_event["id"], serialized_event["index"]))
            if payload:
                payload += b"\n"
            payload += json.dumps(serialized_event).encode("utf-8")
        data = gzip.compress(payload)
        response = self.session.post(self.endpoint_url, data=data)
        response.raise_for_status()
        return event_keys


# Serializers


class PantherStoreSerializer(serializers.Serializer):
    endpoint_url = serializers.URLField()
    bearer_token = serializers.CharField(min_length=1)
    batch_size = serializers.IntegerField(
        default=1,
        min_value=1,
        max_value=PantherStore.max_batch_size,
    )

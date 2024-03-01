import gzip
from kombu.utils import json
import requests
from zentral.core.exceptions import ImproperlyConfigured
from zentral.core.stores.backends.base import BaseEventStore


class EventStore(BaseEventStore):
    max_batch_size = 100

    def __init__(self, config_d):
        super().__init__(config_d)
        endpoint_url = config_d.get("endpoint_url")
        if endpoint_url:
            self.endpoint_url = endpoint_url
        else:
            raise ImproperlyConfigured("Missing or empty endpoint_url")
        bearer_token = config_d.get("bearer_token")
        if not bearer_token:
            raise ImproperlyConfigured("Missing or empty bearer_token")
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {bearer_token}',
            'Content-Encoding': 'gzip'
        })

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

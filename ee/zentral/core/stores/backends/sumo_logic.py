import gzip
from kombu.utils import json
import requests
from zentral.core.exceptions import ImproperlyConfigured
from zentral.core.stores.backends.base import BaseEventStore


class EventStore(BaseEventStore):
    max_batch_size = 100

    def __init__(self, config_d):
        super().__init__(config_d)
        try:
            self.collector_url = config_d["collector_url"]
        except KeyError:
            raise ImproperlyConfigured("Missing collector_url")
        self.session = requests.Session()
        self.session.headers.update({'Content-Encoding': 'gzip'})

    def _serialize_event(self, event):
        if not isinstance(event, dict):
            event_d = event.serialize()
        else:
            event_d = event
        sl_event_d = event_d.pop("_zentral")
        event_type = sl_event_d.get("type")
        namespace = sl_event_d.get("namespace", event_type)
        sl_event_d[namespace] = event_d
        return sl_event_d

    def store(self, event):
        sl_event_d = self._serialize_event(event)
        data = gzip.compress(json.dumps(sl_event_d).encode("utf-8"))
        response = self.session.post(self.collector_url, data=data)
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
        response = self.session.post(self.collector_url, data=data)
        response.raise_for_status()
        return event_keys

from datetime import datetime
import logging
import random
import time
from urllib.parse import urljoin
import requests
from zentral.core.stores.backends.base import BaseEventStore


logger = logging.getLogger('zentral.core.stores.backends.splunk')


class EventStore(BaseEventStore):
    max_retries = 3

    def __init__(self, config_d):
        super().__init__(config_d)
        self.collector_url = urljoin(config_d["hec_url"], "/services/collector/event")
        self.session = requests.Session()
        self.session.verify = config_d.get('verify_tls', True)
        self.session.headers.update({
            'Authorization': "Splunk {}".format(config_d["api_token"])
        })
        self.splunk_metadata = {k: v for k, v in ((attr, config_d.get(attr)) for attr in ("source", "index")) if v}

    @staticmethod
    def _convert_datetime(dt):
        dt = datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S.%f")
        ts = time.mktime(dt.timetuple()) + dt.microsecond / 1e6
        return "{:.3f}".format(ts)

    def _serialize_event(self, event):
        if not isinstance(event, dict):
            event = event.serialize()
        payload_event = event.pop("_zentral")
        created_at = payload_event.pop("created_at")
        event_type = payload_event.pop("type")
        payload_event[event_type] = event
        payload = {
            "host": (payload_event.get("machine_serial_number")
                     or payload_event.get("observer", {}).get("hostname")
                     or "Zentral"),
            "sourcetype": event_type,
            "time": self._convert_datetime(created_at),
            "event": payload_event,
        }
        payload.update(self.splunk_metadata)
        return payload

    def store(self, event):
        payload = self._serialize_event(event)
        for i in range(self.max_retries):
            r = self.session.post(self.collector_url, json=payload)
            if r.ok:
                return
            if r.status_code > 500:
                logger.error("Temporary server error")
                if i + 1 < self.max_retries:
                    seconds = random.uniform(3, 4) * (i + 1)
                    logger.error("Retry in %.1fs", seconds)
                    time.sleep(seconds)
                    continue
            r.raise_for_status()

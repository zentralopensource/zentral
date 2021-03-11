from datetime import datetime
import logging
import random
import time
from urllib.parse import urlencode, urljoin
from django.utils.functional import cached_property
import requests
from zentral.core.stores.backends.base import BaseEventStore


logger = logging.getLogger('zentral.core.stores.backends.splunk')


class EventStore(BaseEventStore):
    max_retries = 3

    def __init__(self, config_d):
        super().__init__(config_d)
        self.collector_url = urljoin(config_d["hec_url"], "/services/collector/event")
        self.hec_token = config_d["hec_token"]
        self.search_app_url = config_d.get("search_app_url")
        if self.search_app_url:
            self.machine_events_url = True
            self.probe_events_url = True
        self.verify_tls = config_d.get('verify_tls', True)
        self.index = config_d.get("index")
        self.source = config_d.get("source")
        self._collector_session = None

    @cached_property
    def collector_session(self):
        session = requests.Session()
        session.verify = self.verify_tls
        session.headers.update({'Authorization': "Splunk {}".format(self.hec_token)})
        return session

    @staticmethod
    def _convert_datetime(dt):
        if isinstance(dt, str):
            dt = datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S.%f")
        ts = time.mktime(dt.timetuple()) + dt.microsecond / 1e6
        return "{:.3f}".format(ts)

    def _serialize_event(self, event):
        if not isinstance(event, dict):
            event = event.serialize()
        payload_event = event.pop("_zentral")
        created_at = payload_event.pop("created_at")
        event_type = payload_event.pop("type")
        namespace = payload_event.get("namespace", event_type)
        payload_event[namespace] = event
        payload = {
            "host": (payload_event.get("machine_serial_number")
                     or payload_event.get("observer", {}).get("hostname")
                     or "Zentral"),
            "sourcetype": event_type,
            "time": self._convert_datetime(created_at),
            "event": payload_event,
        }
        if self.index:
            payload["index"] = self.index
        if self.source:
            payload["source"] = self.source
        return payload

    def store(self, event):
        payload = self._serialize_event(event)
        for i in range(self.max_retries):
            r = self.collector_session.post(self.collector_url, json=payload)
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

    def _get_search_url(self, query, from_dt, to_dt):
        kwargs = {
            "q": f"search {query}",
            "earliest": self._convert_datetime(from_dt),
            "latest": self._convert_datetime(to_dt) if to_dt else "now"
        }
        return "{}?{}".format(self.search_app_url, urlencode(kwargs))

    # machine events

    def _get_machine_events_query(self, serial_number, event_type=None):
        query_chunks = [("host", serial_number)]
        if self.index:
            query_chunks.append(("index", self.index))
        if event_type:
            query_chunks.append(("event_type", event_type))
        return " ".join('{}="{}"'.format(k, v.replace('"', '\\"')) for k, v in query_chunks)

    def get_machine_events_url(self, serial_number, from_dt, to_dt=None, event_type=None):
        return self._get_search_url(
            self._get_machine_events_query(serial_number, event_type),
            from_dt, to_dt
        )

    # probe events

    def _get_probe_events_query(self, probe, event_type=None):
        filter_chunks = []
        if self.index:
            filter_chunks.append(("index", self.index))
        if event_type:
            filter_chunks.append(("event_type", event_type))
        filter_str = " ".join('{}="{}"'.format(k, v.replace('"', '\\"')) for k, v in filter_chunks)
        return f'{filter_str} | spath "probes{{}}.pk" | search "probes{{}}.pk"={probe.pk}'

    def get_probe_events_url(self, probe, from_dt, to_dt=None, event_type=None):
        return self._get_search_url(
            self._get_probe_events_query(probe, event_type),
            from_dt, to_dt
        )

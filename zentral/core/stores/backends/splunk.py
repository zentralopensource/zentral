from datetime import datetime
import json
import logging
import random
import time
from urllib.parse import urlencode, urljoin
from django.utils.functional import cached_property
from django.utils.text import slugify
import requests
from zentral.core.stores.backends.base import BaseEventStore


logger = logging.getLogger('zentral.core.stores.backends.splunk')


class EventStore(BaseEventStore):
    max_batch_size = 100
    max_retries = 3

    def __init__(self, config_d):
        super().__init__(config_d)
        self.collector_url = urljoin(config_d["hec_url"], "/services/collector/event")
        self.hec_token = config_d["hec_token"]
        self.search_app_url = config_d.get("search_app_url")
        # If set, the computer name of the machine snapshots of these sources will be used
        # as host field value. First source with a non-empty value will be picked.
        self.computer_name_as_host_sources = [
            slugify(src)
            for src in config_d.get("computer_name_as_host_sources", [])
        ]
        self.serial_number_field = config_d.get("serial_number_field", "machine_serial_number")
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
        session.headers.update({'Authorization': f'Splunk {self.hec_token}',
                                'Content-Type': 'application/json'})
        return session

    @staticmethod
    def _convert_datetime(dt):
        if isinstance(dt, str):
            dt = dt.replace("+00:00", "").replace("Z", "").strip()
            if "." in dt:
                fmt = "%Y-%m-%dT%H:%M:%S.%f"
            else:
                fmt = "%Y-%m-%dT%H:%M:%S"
            dt = datetime.strptime(dt, fmt)
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
        # host / serial number
        host = "Zentral"
        machine_serial_number = payload_event.pop("machine_serial_number", None)
        if machine_serial_number:
            payload_event[self.serial_number_field] = machine_serial_number
            host = machine_serial_number
            for ms_src_slug in self.computer_name_as_host_sources:
                machine_name = payload_event.get("machine", {}).get(ms_src_slug, {}).get("name")
                if machine_name:
                    host = machine_name
                    break
        else:
            observer = payload_event.get("observer", {}).get("hostname")
            if observer:
                host = observer
        payload = {
            "host": host,
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

    def bulk_store(self, events):
        if self.batch_size < 2:
            raise RuntimeError("bulk_store is not available when batch_size < 2")
        event_keys = []
        data = b""
        for event in events:
            payload = self._serialize_event(event)
            event_keys.append((payload["event"]["id"], payload["event"]["index"]))
            if data:
                data += b"\n"
            data += json.dumps(payload).encode("utf-8")
        for i in range(self.max_retries):
            r = self.collector_session.post(self.collector_url, data=data)
            if r.ok:
                return event_keys
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
            query_chunks.append(("sourcetype", event_type))
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
            filter_chunks.append(("sourcetype", event_type))
        filter_str = " ".join('{}="{}"'.format(k, v.replace('"', '\\"')) for k, v in filter_chunks)
        return f'{filter_str} | spath "probes{{}}.pk" | search "probes{{}}.pk"={probe.pk}'

    def get_probe_events_url(self, probe, from_dt, to_dt=None, event_type=None):
        return self._get_search_url(
            self._get_probe_events_query(probe, event_type),
            from_dt, to_dt
        )

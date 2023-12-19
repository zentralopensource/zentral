from datetime import datetime, timedelta
import json
import logging
import random
import time
import uuid
from urllib.parse import urlencode, urljoin
from defusedxml.ElementTree import fromstring, ParseError
from django.utils.functional import cached_property
from django.utils.text import slugify
from django.utils.timezone import is_aware, make_naive
import requests
from zentral.core.events import event_from_event_d, event_types
from zentral.core.stores.backends.base import BaseEventStore


logger = logging.getLogger('zentral.core.stores.backends.splunk')


class EventStore(BaseEventStore):
    max_batch_size = 100
    max_retries = 3

    def __init__(self, config_d):
        super().__init__(config_d)
        self.hec_url = urljoin(config_d["hec_url"], "/services/collector/event")
        logger.info("HEC URL: %s", self.hec_url)
        self.hec_extra_headers = config_d.get("hec_extra_headers")
        self.hec_token = config_d["hec_token"]
        self.hec_request_timeout = int(config_d.get("hec_request_timeout", 300))
        logger.info("HEC request timeout: %ds", self.hec_request_timeout)
        self.search_app_url = config_d.get("search_app_url")
        # If set, the computer name of the machine snapshots of these sources will be used
        # as host field value. First source with a non-empty value will be picked.
        self.computer_name_as_host_sources = [
            slugify(src)
            for src in config_d.get("computer_name_as_host_sources", [])
        ]
        # Extra custom field to copy the host metadata field to.
        self.custom_host_field = config_d.get("custom_host_field")
        self.serial_number_field = config_d.get("serial_number_field", "machine_serial_number")
        if self.search_app_url:
            self.machine_events_url = True
            self.object_events_url = True
            self.probe_events_url = True
        self.verify_tls = config_d.get('verify_tls', True)
        self.index = config_d.get("index")
        self.source = config_d.get("source")
        # search
        self.authentication_token = config_d.get("authentication_token")
        self.search_url = config_d.get("search_url")
        self.search_extra_headers = config_d.get("search_extra_headers")
        self.search_source = config_d.get("search_source")
        self.search_timeout = int(config_d.get("search_timeout", 300))
        if self.search_url and self.authentication_token:
            self.last_machine_heartbeats = True
            self.machine_events = True
            self.object_events = True
            self.probe_events = True

    @cached_property
    def hec_session(self):
        session = requests.Session()
        session.verify = self.verify_tls
        session.headers.update({'Authorization': f'Splunk {self.hec_token}',
                                'Content-Type': 'application/json'})
        if self.hec_extra_headers:
            for k, v in self.hec_extra_headers.items():
                if k.lower() in ('authorization', 'content-type'):
                    logger.error("Skip '%s' HEC extra header", k)
                else:
                    logger.info("HEC extra header: %s", k)
                    session.headers[k] = v
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
        # index is a reserved Splunk field
        payload_event["id"] = f'{payload_event["id"]}:{payload_event.pop("index")}'
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
        if self.custom_host_field:
            payload_event[self.custom_host_field] = host
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

    def _deserialize_event(self, result):
        metadata = json.loads(result["_raw"])
        # extract id and index from the id field
        try:
            metadata["id"], index = metadata["id"].split(":")
            metadata["index"] = int(index)
        except ValueError:
            # legacy event?
            pass
        # normalize serial number
        if self.serial_number_field in metadata:
            metadata["machine_serial_number"] = metadata.pop(self.serial_number_field)
        # drop custom host field
        if self.custom_host_field:
            metadata.pop(self.custom_host_field, None)
        # add created at
        metadata["created_at"] = result["_time"]
        # event type
        event_type = result["sourcetype"]
        metadata["type"] = event_type
        # event data
        namespace = metadata.get("namespace", event_type)
        event_d = metadata.pop(namespace)
        event_d["_zentral"] = metadata
        return event_from_event_d(event_d)

    def store(self, event):
        payload = self._serialize_event(event)
        for i in range(self.max_retries):
            r = self.hec_session.post(self.hec_url, json=payload, timeout=self.hec_request_timeout)
            if r.ok:
                return
            if r.status_code > 500:
                logger.error("HEC status code %s for store request", r.status_code)
                if i + 1 < self.max_retries:
                    seconds = random.uniform(3, 4) * (i + 1)
                    logger.error("Retry HEC store request in %.1fs", seconds)
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
            event_id, event_index = payload["event"]["id"].split(":")
            event_keys.append((event_id, int(event_index)))
            if data:
                data += b"\n"
            data += json.dumps(payload).encode("utf-8")
        for i in range(self.max_retries):
            r = self.hec_session.post(self.hec_url, data=data, timeout=self.hec_request_timeout)
            if r.ok:
                return event_keys
            if r.status_code > 500:
                logger.error("HEC status code %s for bulk store request", r.status_code)
                if i + 1 < self.max_retries:
                    seconds = random.uniform(3, 4) * (i + 1)
                    logger.error("Retry HEC bulk store request in %.1fs", seconds)
                    time.sleep(seconds)
                    continue
            r.raise_for_status()

    # event methods

    @cached_property
    def search_session(self):
        session = requests.Session()
        session.verify = self.verify_tls
        session.headers.update({'Authorization': f'Bearer {self.authentication_token}',
                                'Content-Type': 'application/json'})
        if self.search_extra_headers:
            for k, v in self.search_extra_headers.items():
                if k.lower() in ('authorization', 'content-type'):
                    logger.error("Skip '%s' search extra header", k)
                else:
                    logger.debug("Set '%s' search extra header", k)
                    session.headers[k] = v
        return session

    def _build_filters(self, event_type=None, serial_number=None, excluded_event_type=None, tag=None):
        filters = []
        if self.index:
            filters.append(("index", self.index))
        if self.search_source:
            filters.append(("source", self.search_source))
        if event_type:
            filters.append(("sourcetype", event_type))
        if serial_number:
            if not self.computer_name_as_host_sources:
                filters.append(("host", serial_number))
            else:
                filters.append((self.serial_number_field, serial_number))
        if excluded_event_type:
            filters.append(("sourcetype!", excluded_event_type))
        pipeline = " ".join('{}="{}"'.format(k, v.replace('"', '\\"')) for k, v in filters)
        if tag:
            tag = tag.replace('"', '\\"')
            pipeline = f'{pipeline} | rename tags{{}} AS tagvalue | where (tagvalue = "{tag}")'
        return pipeline

    def _get_search_url(self, query, from_dt, to_dt):
        kwargs = {
            "q": f"search {query}",
            "earliest": self._convert_datetime(from_dt),
            "latest": self._convert_datetime(to_dt) if to_dt else "now"
        }
        return "{}?{}".format(self.search_app_url, urlencode(kwargs))

    def _post_search_job(self, search, from_dt, to_dt):
        data = {"exec_mode": "blocking",
                "id": str(uuid.uuid4()),
                "search": f"search {search}",
                "earliest_time": from_dt.isoformat(),
                "timeout": self.search_timeout}
        if to_dt:
            data["latest_time"] = to_dt.isoformat()
        r = self.search_session.post(
            urljoin(self.search_url, "/services/search/jobs"),
            data=data
        )
        r.raise_for_status()
        try:
            response = fromstring(r.content)
        except ParseError:
            raise
        return response.find("sid").text

    def _get_search_results(self, sid, offset=0, count=100000):
        r = self.search_session.get(
            urljoin(self.search_url, f"/services/search/jobs/{sid}/results"),
            params={"offset": offset, "count": count, "output_mode": "json"}
        )
        r.raise_for_status()
        return r.json()

    def _fetch_aggregated_event_counts(self, query, from_dt, to_dt):
        sid = self._post_search_job(f"{query} | stats count by sourcetype", from_dt, to_dt)
        results = self._get_search_results(sid)
        return {r["sourcetype"]: int(r["count"]) for r in results["results"]}

    def _fetch_events(self, query, from_dt, to_dt, limit, cursor):
        if cursor is None:
            sid = self._post_search_job(query, from_dt, to_dt)
            offset = 0
        else:
            sid, offset = cursor.split("$")
            offset = int(offset)
        events = []
        new_cursor = None
        results = self._get_search_results(sid, offset, limit)
        init_offset = results["init_offset"]
        result_count = 0
        for result in results["results"]:
            result_count += 1
            events.append(self._deserialize_event(result))
        if result_count >= limit:
            new_offset = init_offset + result_count
            new_cursor = f"{sid}${new_offset}"
        return events, new_cursor

    # machine events

    def _get_machine_events_query(self, serial_number, event_type=None):
        return self._build_filters(event_type, serial_number)

    def fetch_machine_events(self, serial_number, from_dt, to_dt=None, event_type=None, limit=10, cursor=None):
        return self._fetch_events(
            self._get_machine_events_query(serial_number, event_type),
            from_dt, to_dt, limit, cursor
        )

    def get_aggregated_machine_event_counts(self, serial_number, from_dt, to_dt=None):
        return self._fetch_aggregated_event_counts(
            self._get_machine_events_query(serial_number),
            from_dt, to_dt
        )

    def get_machine_events_url(self, serial_number, from_dt, to_dt=None, event_type=None):
        return self._get_search_url(
            self._get_machine_events_query(serial_number, event_type),
            from_dt, to_dt
        )

    def get_last_machine_heartbeats(self, serial_number, from_dt):
        heartbeats = []
        # heartbeat events
        heartbeat_event_filters = self._build_filters("inventory_heartbeat", serial_number)
        heartbeat_event_search = f"{heartbeat_event_filters} | stats max(_time) by inventory.source.name"
        sid = self._post_search_job(heartbeat_event_search, from_dt, None)
        results = self._get_search_results(sid)
        for result in results["results"]:
            heartbeats.append(
                (event_types["inventory_heartbeat"],
                 result["inventory.source.name"],
                 [(None, datetime.utcfromtimestamp(float(result["max(_time)"])))])
            )
        # other events
        other_event_filters = self._build_filters(serial_number=serial_number,
                                                  excluded_event_type="inventory_heartbeat",
                                                  tag="heartbeat")
        other_event_search = f'{other_event_filters} | stats max(_time) by sourcetype request.user_agent'
        sid = self._post_search_job(other_event_search, from_dt, None)
        event_uas = {}
        results = self._get_search_results(sid)
        for result in results["results"]:
            event_type_class = event_types.get(result["sourcetype"])
            if not event_type_class:
                logger.error("Unknown event type %s", result["sourcetype"])
                continue
            event_uas.setdefault(event_type_class, []).append(
                (result["request.user_agent"], datetime.utcfromtimestamp(float(result["max(_time)"])))
            )
        for event_type_class, ua_max_dates in event_uas.items():
            heartbeats.append((event_type_class, None, ua_max_dates))
        return heartbeats

    # object events

    def _get_object_events_query(self, key, val, event_type=None):
        filters = self._build_filters(event_type)
        val = val.replace('"', '\\"')
        return f'{filters} | spath "objects.{key}{{}}" | search "objects.{key}{{}}"="{val}"'

    def fetch_object_events(self, key, val, from_dt, to_dt=None, event_type=None, limit=10, cursor=None):
        return self._fetch_events(
            self._get_object_events_query(key, val, event_type),
            from_dt, to_dt, limit, cursor
        )

    def get_aggregated_object_event_counts(self, key, val, from_dt, to_dt=None):
        return self._fetch_aggregated_event_counts(
            self._get_object_events_query(key, val),
            from_dt, to_dt
        )

    def get_object_events_url(self, key, val, from_dt, to_dt=None, event_type=None):
        return self._get_search_url(
            self._get_object_events_query(key, val, event_type),
            from_dt, to_dt
        )

    # probe events

    def _get_probe_events_query(self, probe, event_type=None):
        filters = self._build_filters(event_type)
        return f'{filters} | spath "probes{{}}.pk" | search "probes{{}}.pk"={probe.pk}'

    def get_aggregated_probe_event_counts(self, probe, from_dt, to_dt=None):
        return self._fetch_aggregated_event_counts(
            self._get_probe_events_query(probe),
            from_dt, to_dt
        )

    def fetch_probe_events(self, probe, from_dt, to_dt=None, event_type=None, limit=10, cursor=None):
        return self._fetch_events(
            self._get_probe_events_query(probe, event_type),
            from_dt, to_dt, limit, cursor
        )

    def get_probe_events_url(self, probe, from_dt, to_dt=None, event_type=None):
        return self._get_search_url(
            self._get_probe_events_query(probe, event_type),
            from_dt, to_dt
        )

    # zentral apps data

    def get_app_hist_data(self, interval, bucket_number, tag):
        from_dt_truncation = {"minute": 0, "second": 0, "microsecond": 0}
        if interval == "day":
            bucket_span = "1d"
            bucket_seconds = 24 * 3600
            from_dt_truncation["hour"] = 0
        elif interval == "hour":
            bucket_span = "1h"
            bucket_seconds = 3600
        else:
            logger.error("Unsupported interval %s", interval)
            return []
        now = datetime.utcnow()
        from_dt = now - timedelta(seconds=bucket_seconds * bucket_number)
        from_dt = from_dt.replace(**from_dt_truncation)
        filters = self._build_filters(tag=tag)
        search = f"{filters} | bucket _time span={bucket_span} | stats count dc(host) as uniq_msn by _time"
        sid = self._post_search_job(search, from_dt, None)
        results = self._get_search_results(sid)
        dt_results = {}
        for result in results["results"]:
            dt = datetime.strptime(result["_time"], "%Y-%m-%dT%H:%M:%S.%f%z")
            if is_aware(dt):
                dt = make_naive(dt)
            dt_results[dt] = (int(result["count"]), int(result["uniq_msn"]))
        data = []
        current_dt = from_dt
        while current_dt < now:
            count, uniq_msn = dt_results.get(current_dt, (0, 0))
            data.append((current_dt, count, uniq_msn))
            current_dt += timedelta(seconds=bucket_seconds)
        return data[-1*bucket_number:]

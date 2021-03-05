import zlib
import json
import logging
import re
import requests
import time
from zentral.core.events import event_from_event_d
from zentral.core.stores.backends.base import BaseEventStore


logger = logging.getLogger('zentral.core.stores.backends.datadog')


class EventStore(BaseEventStore):
    tag_component_cleanup_re = re.compile(r'[^\w\-/\.]+')

    def __init__(self, config_d):
        super(EventStore, self).__init__(config_d)
        # URLs
        site = config_d.get("site", "datadoghq.com")
        self.input_url = f"https://http-intake.logs.{site}/v1/input"
        self.search_url = f"https://api.{site}/api/v2/logs/events/search"
        self.aggregate_url = f"https://api.{site}/api/v2/logs/analytics/aggregate"

        # Service / Source
        self.service = config_d.get("service", "Zentral")
        self.source = config_d.get("source", "zentral")

        # requests session
        self._session = requests.Session()
        self._session.headers.update({
            'DD-API-KEY': config_d["api_key"],
            'Content-Type': 'application/json',
        })
        app_key = config_d.get("application_key")
        if app_key:
            self._session.headers.update({"DD-APPLICATION-KEY": app_key})

    def _prepare_tag(self, key, value):
        value = self.tag_component_cleanup_re.sub("_", value)
        return "ztl-{}:{}".format(key, value)[:200]

    def _serialize_event(self, event):
        if not isinstance(event, dict):
            event = event.serialize()
        ddevent = event.pop("_zentral")
        event_type = ddevent.pop("type")
        ddevent[event_type] = event
        ddevent["service"] = self.service
        ddevent["ddsource"] = self.source
        ddevent["logger"] = {"name": event_type}
        ddtags = []
        for t in ddevent.pop("tags", []):
            ddtags.append(self._prepare_tag("tag", t))
        ddevent["ddtags"] = ",".join(ddtags)
        ddevent["@timestamp"] = ddevent.pop("created_at")
        ddevent["host"] = (ddevent.get("machine_serial_number")
                           or ddevent.get("observer", {}).get("hostname")
                           or "Zentral")
        request = ddevent.get("request")
        network_client = {}
        http = {}
        usr = {}
        if request:
            ip = request.pop("ip", None)
            if ip:
                network_client["ip"] = ip
            user_agent = request.pop("user_agent", None)
            if user_agent:
                http["useragent"] = user_agent
            user = request.get("user", None)
            if user:
                for ztl_attr, dd_attr in (("id", "id"),
                                          ("email", "email"),
                                          ("username", "name")):
                    val = user.pop(ztl_attr)
                    if val:
                        usr[dd_attr] = str(val)
                if not user:
                    request.pop("user")
            if not request:
                ddevent.pop("request")
        if network_client:
            ddevent["network"] = {"client": network_client}
        if http:
            ddevent["http"] = http
        if usr:
            ddevent["usr"] = usr
        return ddevent

    def _deserialize_event(self, log_d):
        log_attributes = log_d["attributes"]
        metadata = log_attributes["attributes"]
        # tags
        for tag in log_attributes.get("tags", []):
            if tag.startswith("ztl-"):
                tag = tag[4:].split(":", 1)[-1]
                metadata.setdefault("tags", []).append(tag)
        # created_at
        metadata["created_at"] = metadata.pop("@timestamp")
        # extra attributes to cleanup
        metadata.pop("service", None)
        metadata.pop("host", None)
        # request
        request = metadata.setdefault("request", {})
        user_agent = metadata.pop("http", {}).get("useragent")
        if user_agent:
            request["user_agent"] = user_agent
        ip = metadata.pop("network", {}).get("client", {}).get("ip")
        if ip:
            request["ip"] = ip
        usr = metadata.pop("usr", None)
        if usr:
            for dd_attr, ztl_attr in (("id", "id"),
                                      ("email", "email"),
                                      ("name", "username")):
                val = usr.get(dd_attr)
                if val:
                    request.setdefault("user", {})[ztl_attr] = val
        # the real event content
        event_type = metadata.pop("logger")["name"]
        metadata["type"] = event_type
        event_d = metadata.pop(event_type)
        event_d["_zentral"] = metadata
        return event_from_event_d(event_d)

    def store(self, event):
        ddevent = self._serialize_event(event)
        r = self._session.post(
            self.input_url,
            data=zlib.compress(json.dumps([ddevent]).encode("utf-8")),
            headers={"Content-Encoding": "deflate"}
        )
        r.raise_for_status()

    @staticmethod
    def _prepare_datetime(dt):
        return str(int(time.mktime(dt.timetuple())))

    # machine events

    def _get_machine_events_filter(self, serial_number, from_dt, to_dt=None, event_type=None):
        query_chunks = [f"host:{serial_number}"]
        if event_type:
            query_chunks.append(f"@logger.name:{event_type}")
        return {
            "query": " AND ".join(query_chunks),
            "from": self._prepare_datetime(from_dt),
            "to": self._prepare_datetime(to_dt) if to_dt else "now"
        }

    def get_total_machine_event_count(self, serial_number, from_dt, to_dt=None, event_type=None):
        body = {
            "compute": [{"aggregation": "count"}],
            "filter": self._get_machine_events_filter(serial_number, from_dt, to_dt, event_type)
        }
        r = self._session.post(self.aggregate_url, json=body)
        if r.ok:
            response = r.json()
            try:
                return int(response["data"]["buckets"][0]["computes"]["c0"])
            except (KeyError, IndexError, TypeError, ValueError):
                logger.error("Could not extract machine event count from response")
        else:
            logger.error("Could not get machine event count. Status: %s", r.status_code)
        return 0

    def fetch_machine_events(self, serial_number, from_dt, to_dt=None, event_type=None, limit=10, cursor=None):
        body = {
            "filter": self._get_machine_events_filter(serial_number, from_dt, to_dt, event_type),
            "sort": "-timestamp",
            "page": {"limit": limit}
        }
        if cursor:
            body["page"]["cursor"] = cursor
        r = self._session.post(self.search_url, json=body)
        if not r.ok:
            return [], None
        response = r.json()
        data = response.get("data", [])
        if not data:
            return [], None
        events = []
        for log_d in data:
            events.append(self._deserialize_event(log_d))
        next_cursor = None
        if len(events) >= limit:
            try:
                next_cursor = response["meta"]["page"]["after"]
            except KeyError:
                pass
        return events, next_cursor

    def get_aggregated_machine_event_counts(self, serial_number, from_dt, to_dt=None):
        body = {
            "compute": [{"aggregation": "count"}],
            "filter": self._get_machine_events_filter(serial_number, from_dt, to_dt),
            "group_by": [{"facet": "@logger.name"}]
        }
        r = self._session.post(self.aggregate_url, json=body)
        if r.ok:
            response = r.json()
            types_d = {}
            for bucket in response.get("data", {}).get("buckets", []):
                types_d[bucket["by"]["@logger.name"]] = int(bucket["computes"]["c0"])
            return types_d
        else:
            logger.error("Could not get machine event types with usages. Status: %s", r.status_code)
        return {}

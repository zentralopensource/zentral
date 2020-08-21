import zlib
import json
import logging
import re
import requests
from zentral.core.stores.backends.base import BaseEventStore

logger = logging.getLogger('zentral.core.stores.backends.datadog')


class EventStore(BaseEventStore):
    tag_component_cleanup_re = re.compile(r'[^\w\-/\.]+')

    def __init__(self, config_d):
        super(EventStore, self).__init__(config_d)
        # base URL
        site = config_d.get("site", "datadoghq.com")
        self.base_url = "https://http-intake.logs.{}/v1/input".format(site)

        # Service / Source
        self.service = config_d.get("service", "Zentral")
        self.source = config_d.get("source", "zentral")

        # requests session
        self._session = requests.Session()
        self._session.headers.update({
            'DD-API-KEY': config_d["api_key"],
            'Content-Encoding': 'deflate',
            'Content-Type': 'application/json',
        })

    def prepare_tag(self, key, value):
        value = self.tag_component_cleanup_re.sub("_", value)
        return "{}:{}".format(key, value)[:200]

    def store(self, event):
        if not isinstance(event, dict):
            event = event.serialize()
        ddevent = event.pop("_zentral")
        event_type = ddevent.pop("type")
        ddevent[event_type] = event
        ddevent["service"] = self.service
        ddevent["ddsource"] = self.source
        ddevent["evt"] = {"name": event_type}
        ddtags = []
        for t in ddevent.pop("tags", []):
            ddtags.append(self.prepare_tag("ztl/tag", t))
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

        r = self._session.post(
            self.base_url,
            data=zlib.compress(json.dumps([ddevent]).encode("utf-8"))
        )
        r.raise_for_status()

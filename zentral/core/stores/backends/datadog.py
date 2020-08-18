import zlib
import json
import logging
import requests
from zentral.core.stores.backends.base import BaseEventStore

logger = logging.getLogger('zentral.core.stores.backends.datadog')


class EventStore(BaseEventStore):
    def __init__(self, config_d):
        super(EventStore, self).__init__(config_d)
        # base URL
        site = config_d.get("site", "datadoghq.com")
        self.base_url = "https://http-intake.logs.{}/v1/input".format(site)

        # requests session
        self._session = requests.Session()
        self._session.headers.update({
            'DD-API-KEY': config_d["api_key"],
            'Content-Encoding': 'deflate',
            'Content-Type': 'application/json',
        })

    def store(self, event):
        if not isinstance(event, dict):
            event = event.serialize()
        ddevent = event.pop("_zentral")
        event_type = ddevent.pop("type")
        ddevent[event_type] = event
        ddevent["ddsource"] = "Zentral"
        ddevent["ddtags"] = ",".join(t.replace(":", "_") for t in ddevent.pop("tags", []))
        ddevent["service"] = event_type
        ddevent["@timestamp"] = ddevent.pop("created_at")
        ddevent["host"] = (ddevent.get("machine_serial_number")
                           or ddevent.get("observer", {}).get("hostname")
                           or "Zentral")
        r = self._session.post(self.base_url, data=zlib.compress(json.dumps([ddevent]).encode("utf-8")))
        r.raise_for_status()

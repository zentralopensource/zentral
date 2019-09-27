import base64
import collections.abc
from datetime import datetime, timedelta
import hashlib
import hmac
import json
import logging
import pytz
import requests
from zentral.core.events import event_from_event_d
from zentral.core.stores.backends.base import BaseEventStore


logger = logging.getLogger('zentral.core.stroes.backends.azure_log_analytics')


def datetime_to_iso8601z_truncated_to_milliseconds(dt):
    # round created at to milliseconds
    dt_microsecond = dt.microsecond
    if dt_microsecond:
        dt_millisecond = round(dt_microsecond / 1000)
        if dt_millisecond == 1000:
            dt = dt.replace(microsecond=0)
            dt += timedelta(seconds=1)
        else:
            dt = dt.replace(microsecond=1000 * dt_millisecond)

    # convert to UTC only if not naive (python<3.6)
    if dt.utcoffset() is not None:
        dt = dt.astimezone(pytz.utc)

    # ensure naive, convert to isoformat
    dt_iso = dt.replace(tzinfo=None).isoformat()

    # truncate the microseconds in isoformat if necessary
    if "." in dt_iso:
        dt_iso = dt_iso[:-3]

    # add the pseudo time zone
    return "{}Z".format(dt_iso)


class EventStore(BaseEventStore):
    log_type = "ZentralEvent"
    content_type = "application/json"
    resource = "/api/logs"
    url_template = "https://{customer_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

    def __init__(self, config_d):
        super().__init__(config_d)
        # The customer ID to your Log Analytics workspace ID
        self.customer_id = config_d["customer_id"]

        # For the shared key, use either the primary or the secondary Connected Sources client authentication key
        self._shared_key = config_d["shared_key"]
        self._decoded_shared_key = base64.b64decode(self._shared_key)

        # requests session
        self._session = requests.Session()
        self._session.headers.update({
            "Content-Type": self.content_type,
            "Log-Type": self.log_type,
            "time-generated-field": "CreatedAt",  # ISO 8601
        })
        self._url = self.url_template.format(customer_id=self.customer_id)

    def _flatten_metadata(self, metadata, parent_key=''):
        items = []
        for k, v in metadata.items():
            export_k = "".join(s.title() for s in k.split("_"))
            new_key = parent_key + export_k if parent_key else export_k
            if isinstance(v, collections.abc.MutableMapping):
                items.extend(self._flatten_metadata(v, new_key).items())
            else:
                items.append((new_key, v))
        return dict(items)

    def _prepare_event(self, event):
        event_d = event.serialize()

        metadata = event_d.pop("_zentral")

        # fix created_at format for use as TimeGenerated field via the time-generated-field header
        metadata["created_at"] = datetime_to_iso8601z_truncated_to_milliseconds(event.metadata.created_at)

        # flatten the metadata
        azure_event = self._flatten_metadata(metadata)

        # add the rest of the data
        azure_event["Properties"] = event_d
        return [azure_event]

    def _build_signature(self, rfc1123_date, content_length):
        # Build the API signature
        string_to_hash = "\n".join([
            "POST",
            str(content_length),
            self.content_type,
            'x-ms-date:' + rfc1123_date,
            self.resource
        ])
        return base64.b64encode(
            hmac.new(
                self._decoded_shared_key,
                string_to_hash.encode("utf-8"),
                digestmod=hashlib.sha256).digest()
        )

    def store(self, event):
        # Build and send a request to the POST API
        if isinstance(event, dict):
            event = event_from_event_d(event)
        data = json.dumps(self._prepare_event(event)).encode("utf-8")
        rfc1123_date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        signature = self._build_signature(rfc1123_date, len(data))
        self._session.headers.update({
            'Authorization': "SharedKey {}:{}".format(self.customer_id, signature.decode("utf-8")),
            'x-ms-date': rfc1123_date,
        })
        r = self._session.post(self._url, data=data)
        r.raise_for_status()

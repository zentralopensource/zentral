import logging
from urllib.parse import urljoin
import requests
from zentral.core.stores.backends.base import BaseEventStore

logger = logging.getLogger('zentral.core.stores.backends.humio')


class EventStore(BaseEventStore):

    def __init__(self, config_d):
        super(EventStore, self).__init__(config_d)
        # base_url is the humio account base url
        base_url = config_d.pop("base_url")
        # ingest_token is a write only humio api token linked to a repository
        ingest_token = config_d.pop("ingest_token")
        self.ingest_url = urljoin(base_url, "/api/v1/ingest/humio-structured")

        # requests session
        self._session = requests.Session()
        self._session.headers.update({
            'Content-Type': 'application/json',
            'Authorization': "Bearer {}".format(ingest_token)
        })

    def _serialize_event(self, event):
        if not isinstance(event, dict):
            event = event.serialize()
        humio_attributes = event.pop("_zentral")
        event_type = humio_attributes.pop("type")
        humio_tags = {"event_type": event_type}
        namespace = humio_attributes.get("namespace", event_type)
        humio_attributes[namespace] = event
        created_at = humio_attributes.pop("created_at")
        timestamp = "{}Z".format(created_at[:-3])
        return [{"tags": humio_tags, "events": [{"timestamp": timestamp, "attributes": humio_attributes}]}]

    def store(self, event):
        r = self._session.post(self.ingest_url, json=self._serialize_event(event))
        r.raise_for_status()

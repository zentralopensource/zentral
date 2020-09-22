#    base.json - example config
#    "humio": {
#      "frontend": true,
#      "backend": "zentral.core.stores.backends.humio",
#      "ingest_url": "https://cloud.humio.com/api/v1/ingest/humio-unstructured",
#      "ingest_token": "<ingest_token_here>",
#      "verify_tls": true
#    }

import json
import logging
import requests
from zentral.core.stores.backends.base import BaseEventStore

logger = logging.getLogger('zentral.core.stores.backends.humio')


class EventStore(BaseEventStore):
    def __init__(self, config_d):
        super(EventStore, self).__init__(config_d)
        self.base_url = config_d.get("ingest_url")
        api_token = config_d.get("ingest_token")
        verify_tls = config_d.get('verify_tls', True)

        # requests session
        self._session = requests.Session()
        self._session.verify = verify_tls
        self._session.headers.update({
            'Content-Type': 'application/json',
            'Authorization': "Bearer {}".format(api_token)
        })

    def store(self, event):
        if not isinstance(event, dict):
            event = event.serialize()
        event_data = json.dumps(event)
        # humio requires event preformatting - https://docs.humio.com/api/ingest/
        data = json.dumps([{"messages": [f'{event_data}']}])
        r = self._session.post(self.base_url, data=data)
        r.raise_for_status()



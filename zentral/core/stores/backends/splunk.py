import logging
import requests
from zentral.core.stores.backends.base import BaseEventStore

logger = logging.getLogger('zentral.core.stores.backends.splunk')


class EventStore(BaseEventStore):
    def __init__(self, config_d):
        super(EventStore, self).__init__(config_d)
        self.base_url = config_d.get("base_url")
        api_token = config_d.get("api_token")
        verify_tls = config_d.get('verify_tls', True)

        # requests session
        self._session = requests.Session()
        self._session.verify = verify_tls
        self._session.headers.update({
            'Authorization': "Splunk {}".format(api_token)
        })

    def store(self, event):
        if not isinstance(event, dict):
            event = event.serialize()
        r = self._session.post(self.base_url, json=event)
        r.raise_for_status()

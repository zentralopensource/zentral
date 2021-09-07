import logging
import random
import time
from django.utils.functional import cached_property
import requests
from zentral.core.stores.backends.base import BaseEventStore


logger = logging.getLogger('zentral.core.stores.backends.http')


class EventStore(BaseEventStore):
    max_retries = 3

    def __init__(self, config_d):
        super().__init__(config_d)
        self.endpoint_url = config_d["endpoint_url"]
        self.verify_tls = config_d.get('verify_tls', True)
        self.headers = config_d.get("headers")
        self.username = config_d.get("username")
        self.password = config_d.get("password")
        if self.username and not self.password:
            logger.error("Username set without password")
        elif self.password and not self.username:
            logger.error("Password set without username")
        elif self.headers and self.password and self.username and "AUTHORIZATION" in (k.upper() for k in self.headers):
            logger.error("Basic auth AND Authorization header cannot be both configured")
        self._session = None

    @cached_property
    def session(self):
        session = requests.Session()
        session.verify = self.verify_tls
        session.headers.update({'Content-Type': 'application/json'})
        if self.headers:
            session.headers.update(self.headers)
        if self.username and self.password:
            session.auth = (self.username, self.password)
        return session

    def _serialize_event(self, event):
        if not isinstance(event, dict):
            event = event.serialize()
        payload = event.pop("_zentral")
        event_type = payload.get("type")
        namespace = payload.get("namespace", event_type)
        payload[namespace] = event
        return payload

    def store(self, event):
        payload = self._serialize_event(event)
        for i in range(self.max_retries):
            r = self.session.post(self.endpoint_url, json=payload)
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

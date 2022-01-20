import requests
from .base import BaseAction


class Action(BaseAction):
    def __init__(self, config_d):
        super().__init__(config_d)
        self.url = config_d['webhook']

    def trigger(self, event, probe, action_config_d):
        r = requests.post(
            self.url,
            headers={'Accept': 'application/json'},
            json={'text': '\n\n'.join([event.get_notification_subject(probe),
                                       event.get_notification_body(probe)])}
        )
        r.raise_for_status()

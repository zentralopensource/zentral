import requests
from .base import BaseAction


class Action(BaseAction):
    def trigger(self, event, probe, action_config_d):
        action_config_d = action_config_d or {}
        payload = {'text': '\n\n'.join([event.get_notification_subject(probe),
                                        event.get_notification_body(probe)])}
        url = self.config_d['webhook']
        r = requests.post(url, json=payload)
        r.raise_for_status()

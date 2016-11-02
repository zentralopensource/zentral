import json
import requests
from .base import BaseAction

API_ENDPOINT_TMPL = "https://slack.com/api/{}"


class Action(BaseAction):
    def trigger(self, event, probe, action_config_d):
        action_config_d = action_config_d or {}
        args = {'text': '\n\n'.join([event.get_notification_subject(probe),
                                     event.get_notification_body(probe)])}
        url = self.config_d['webhook']
        r = requests.post(url,
                          headers={'Accept': 'application/json'},
                          data=json.dumps(args))
        r.raise_for_status()

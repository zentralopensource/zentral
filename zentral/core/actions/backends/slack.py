import json
import requests
from .base import BaseAction

API_ENDPOINT = "https://slack.com/api/chat.postMessage"


class Action(BaseAction):
    def trigger(self, event, probe, action_config_d):
        action_config_d = action_config_d or {}
        args = {'text': '\n\n'.join([event.get_notification_subject(probe),
                                     event.get_notification_body(probe)])}
        if 'webhook' not in self.config_d:
            args.update({'token': self.config_d['token'],
                         'username': self.config_d['username'],
                         'channel': action_config_d.get('channel', self.config_d['channel'])})
            url = API_ENDPOINT
        else:
            url = self.config_d['webhook']
        requests.post(url, headers={'Accept': 'application/json'}, data=json.dumps(args))

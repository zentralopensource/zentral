import requests
from .base import BaseAction
from zentral.conf import contact_groups

API_ENDPOINT = "https://api.pushover.net/1/messages.json"


class Action(BaseAction):
    def trigger(self, event, probe, action_config_d):
        action_config_d = action_config_d or {}
        args = {'message': '\n\n'.join([event.get_notification_subject(probe),
                                        event.get_notification_body(probe)]),
                'token': self.config_d['token']}
        for group_name in action_config_d['groups']:
            for contact_d in contact_groups[group_name]:
                pushover_user_token = contact_d.get('pushover_user_token', None)
                if pushover_user_token:
                    args['user'] = pushover_user_token
                    requests.post(API_ENDPOINT, data=args)

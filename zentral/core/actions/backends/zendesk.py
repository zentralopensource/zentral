import json
import logging
import requests
from .base import BaseAction

logger = logging.getLogger('zentral.core.actions.backends.zendesk')

API_ENDPOINT = "https://apfelwerksupport.zendesk.com/api/v2/tickets.json"

​
class Action(BaseAction):
    def __init__(self, config_d):
        super(Action, self).__init__(config_d)
        self.auth = ('{email}/token'.format(config_d), config_d['token'])

    def trigger(self, event, action_config_d):
        action_config_d = action_config_d or {}
        args = {'ticket': {'comment': {'body': event.get_notification_body()},
                'subject': event.get_notification_subject()}}

        # priority
        priority = action_config_d.get('priority', 'normal')
        if priority not in ('urgent', 'high', 'normal', 'low'):
            logger.warning('Invalid priority level %s', priority)
            priority = 'normal'
        args['priority'] = priority

        # tags
        tags = action_config_d.get('tags', None)
        if tags:
            args['tags'] = tags

        requests.post(API_ENDPOINT, headers={'Content-Type': 'application/json'},
                     data=json.dumps(args), auth=self.auth)

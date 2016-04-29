import json
import logging
import requests
from .base import BaseAction

logger = logging.getLogger('zentral.core.actions.backends.zendesk')

API_ENDPOINT = "https://{subdomain}.zendesk.com/api/v2/tickets.json"


class Action(BaseAction):
    def __init__(self, config_d):
        super(Action, self).__init__(config_d)
        self.auth = ('{email}/token'.format(**config_d), config_d['token'])
        self.url = API_ENDPOINT.format(**config_d)

    def trigger(self, event, probe, action_config_d):
        action_config_d = action_config_d or {}
        args = {'ticket': {'comment': {'body': event.get_notification_body(probe)},
                'subject': event.get_notification_subject(probe)}}

        # priority
        priority = action_config_d.get('priority', 'normal')
        if priority not in ('urgent', 'high', 'normal', 'low'):
            logger.warning('Invalid priority level %s', priority)
            priority = 'normal'
        args['ticket']['priority'] = priority

        # tags
        tags = action_config_d.get('tags', None)
        if tags:
            args['ticket']['tags'] = tags

        r = requests.post(self.url, headers={'Content-Type': 'application/json'},
                          data=json.dumps(args), auth=self.auth)
        r.raise_for_status()

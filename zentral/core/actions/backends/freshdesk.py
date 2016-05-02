# example: https://raw.githubusercontent.com/freshdesk/fresh-samples/master/Python/create_ticket.py
import json
import logging
import requests
from .base import BaseAction

logger = logging.getLogger('zentral.core.actions.backends.freshdesk')

API_ENDPOINT = "https://{subdomain}.freshdesk.com/api/v2/tickets"


class Action(BaseAction):
    PRIORITIES = {'low': 1, 'medium': 2, 'high': 3, 'urgent': 4}
    STATUSES = {'open': 2, 'pending': 3, 'resolved': 4, 'closed': 5}

    def __init__(self, config_d):
        super(Action, self).__init__(config_d)
        self.auth = (config_d['api_key'], config_d['password'])
        self.url = API_ENDPOINT.format(**config_d)
        self.default_ticket_email = config_d['default_ticket_email']

    def trigger(self, event, probe, action_config_d):
        action_config_d = action_config_d or {}
        action_config_d = action_config_d.copy()
        args = {'subject': event.get_notification_subject(probe),
                'description': event.get_notification_body(probe),
                'email': action_config_d.pop('email', self.default_ticket_email)}

        priority = action_config_d.pop('priority', 'medium').lower()
        if priority not in self.PRIORITIES:
            logger.warning('Invalid priority level %s', priority)
            priority = 'medium'
        args['priority'] = self.PRIORITIES[priority]

        status = action_config_d.pop('status', 'open').lower()
        if status not in self.STATUSES:
            logger.warning('Invalid status level %s', status)
            status = '2'
        args['status'] = self.STATUSES[status]

        tags = action_config_d.pop('tags', None)
        if tags:
            args['tags'] = tags
        args.update(action_config_d)
        r = requests.post(self.url, headers={'Content-Type': 'application/json'},
                          data=json.dumps(args), auth=self.auth)
        if not r.ok:
            logger.error(r.text)
        r.raise_for_status()

# example: https://raw.githubusercontent.com/freshdesk/fresh-samples/master/Python/create_ticket.py
import json
import logging
from django import forms
import requests
from zentral.utils.forms import CommaSeparatedQuotedStringField
from .base import BaseAction, BaseActionForm

logger = logging.getLogger('zentral.core.actions.backends.freshdesk')

API_ENDPOINT = "https://{subdomain}.freshdesk.com/api/v2/tickets"

PRIORITIES = {'low': 1, 'medium': 2, 'high': 3, 'urgent': 4}
DEFAULT_PRIORITY = 'medium'
STATUSES = {'open': 2, 'pending': 3, 'resolved': 4, 'closed': 5}
DEFAULT_STATUS = 'open'


class ActionForm(BaseActionForm):
    email = forms.EmailField(label="ticket email", required=False)
    priority = forms.ChoiceField(choices=[(p, p) for p in PRIORITIES], initial=DEFAULT_PRIORITY)
    status = forms.ChoiceField(choices=[(s, s) for s in STATUSES], initial=DEFAULT_STATUS)
    tags = CommaSeparatedQuotedStringField(required=False,
                                           help_text=('Comma separated tag list. '
                                                      'Quote the tags with "" if they contain a comma.'))


class Action(BaseAction):
    action_form_class = ActionForm

    def __init__(self, config_d):
        super(Action, self).__init__(config_d)
        self.auth = (config_d['api_key'], config_d['password'])
        self.url = API_ENDPOINT.format(**config_d)
        self.default_ticket_email = config_d['default_ticket_email']
        self.extra_attributes = config_d.get("extra_attributes", {})

    def trigger(self, event, probe, action_config_d):
        action_config_d = action_config_d or {}
        action_config_d = action_config_d.copy()
        args = {'subject': event.get_notification_subject(probe),
                'description': event.get_notification_body(probe),
                'email': action_config_d.pop('email', self.default_ticket_email)}
        args.update(self.extra_attributes)

        priority = action_config_d.pop('priority', 'medium').lower()
        if priority not in PRIORITIES:
            logger.warning('Invalid priority level %s', priority)
            priority = 'medium'
        args['priority'] = PRIORITIES[priority]

        status = action_config_d.pop('status', 'open').lower()
        if status not in STATUSES:
            logger.warning('Invalid status level %s', status)
            status = 'open'
        args['status'] = STATUSES[status]

        tags = action_config_d.pop('tags', None)
        if tags:
            args['tags'] = tags
        args.update(action_config_d)
        r = requests.post(self.url, headers={'Content-Type': 'application/json'},
                          data=json.dumps(args), auth=self.auth)
        if not r.ok:
            logger.error(r.text)
        r.raise_for_status()

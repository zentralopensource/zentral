import json
import logging
from django import forms
import requests
from zentral.core.actions.backends.base import BaseAction, BaseActionForm
from zentral.utils.forms import CommaSeparatedQuotedStringField


logger = logging.getLogger('zentral.contrib.zendesk.actions.ticket')

API_ENDPOINT = "https://{subdomain}.zendesk.com/api/v2/tickets.json"

PRIORITIES = ["low", "normal", "high", "urgent"]
DEFAULT_PRIORITY = "normal"


class ActionForm(BaseActionForm):
    priority = forms.ChoiceField(choices=[(p, p) for p in PRIORITIES], initial=DEFAULT_PRIORITY)
    tags = CommaSeparatedQuotedStringField(required=False,
                                           help_text=('Comma separated tag list. '
                                                      'Quote the tags with "" if they contain a comma.'))


class Action(BaseAction):
    action_form_class = ActionForm

    def _prepare_tag_set(self, tags):
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(',') if t.strip()]
        if not isinstance(tags, list):
            logger.error('Wrong tag configuration for action %s', self.name)
            tags = []
        return set(tags)

    def __init__(self, config_d):
        super(Action, self).__init__(config_d)
        self.auth = ('{email}/token'.format(**config_d), config_d['token'])
        self.url = API_ENDPOINT.format(**config_d)
        self.default_tag_set = self._prepare_tag_set(config_d.get('tags', []))

    def trigger(self, event, probe, action_config_d):
        action_config_d = action_config_d or {}
        args = {'ticket': {'comment': {'body': event.get_notification_body(probe)},
                'subject': event.get_notification_subject(probe)}}

        # priority
        priority = action_config_d.get('priority', DEFAULT_PRIORITY)
        if priority not in PRIORITIES:
            logger.warning('Invalid priority level %s', priority)
            priority = DEFAULT_PRIORITY
        args['ticket']['priority'] = priority

        # tags
        action_tag_set = self._prepare_tag_set(action_config_d.get('tags', []))
        tag_set = action_tag_set | self.default_tag_set
        if tag_set:
            args['ticket']['tags'] = list(tag_set)

        r = requests.post(self.url, headers={'Content-Type': 'application/json'},
                          data=json.dumps(args), auth=self.auth)
        r.raise_for_status()

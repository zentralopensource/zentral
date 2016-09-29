import json
import logging
import requests
from zentral.core.actions.backends.base import BaseAction


logger = logging.getLogger('zentral.contrib.zendesk.actions.ticket')

API_ENDPOINT = "https://{subdomain}.zendesk.com/api/v2/tickets.json"


class Action(BaseAction):
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
        priority = action_config_d.get('priority', 'normal')
        if priority not in ('urgent', 'high', 'normal', 'low'):
            logger.warning('Invalid priority level %s', priority)
            priority = 'normal'
        args['ticket']['priority'] = priority

        # tags
        action_tag_set = self._prepare_tag_set(action_config_d.get('tags', []))
        tag_set = action_tag_set | self.default_tag_set
        if tag_set:
            args['ticket']['tags'] = list(tag_set)

        r = requests.post(self.url, headers={'Content-Type': 'application/json'},
                          data=json.dumps(args), auth=self.auth)
        r.raise_for_status()

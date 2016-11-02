import requests
from .base import BaseAction, ContactGroupForm
from zentral.conf import contact_groups

API_ENDPOINT = "https://api.twilio.com/2010-04-01/"


class Action(BaseAction):
    action_form_class = ContactGroupForm

    def __init__(self, config_d):
        super(Action, self).__init__(config_d)
        self.auth = (config_d['account_sid'], config_d['auth_token'])
        self.url = "{api_endpoint}Accounts/{account_sid}/Messages".format(api_endpoint=API_ENDPOINT,
                                                                          account_sid=config_d['account_sid'])
        self.form_class = ContactGroupForm

    def trigger(self, event, probe, action_config_d):
        action_config_d = action_config_d or {}
        args = {'Body': '\n\n'.join([event.get_notification_subject(probe),
                                     event.get_notification_body(probe)]),
                'From': self.config_d['from_number']}
        for group_name in action_config_d['groups']:
            for contact_d in contact_groups[group_name]:
                cell_number = contact_d.get('cell', None)
                if cell_number:
                    args['To'] = cell_number
                    r = requests.post(self.url, data=args, auth=self.auth)
                    r.raise_for_status()

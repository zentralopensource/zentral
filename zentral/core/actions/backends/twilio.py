import requests
from .base import BaseAction


class Action(BaseAction):
    api_endpoint = "https://api.twilio.com/2010-04-01/"

    def __init__(self, config_d):
        super().__init__(config_d)
        account_sid = config_d['account_sid']
        self.auth = (account_sid, config_d['auth_token'])
        self.url = f"{self.api_endpoint}Accounts/{account_sid}/Messages"
        self.from_number = config_d["from_number"]
        self.to_numbers = [n for n in config_d.get("to_numbers", []) if n and isinstance(n, str)]

    def trigger(self, event, probe, action_config_d):
        if not self.to_numbers:
            return
        args = {'Body': '\n\n'.join([event.get_notification_subject(probe),
                                     event.get_notification_body(probe)]),
                'From': self.from_number}
        for number in self.to_numbers:
            args['To'] = number
            r = requests.post(self.url, data=args, auth=self.auth)
            r.raise_for_status()

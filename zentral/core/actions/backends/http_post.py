import json
import requests
from .base import BaseAction


class Action(BaseAction):
    action_form_class = None

    def trigger(self, event, probe, action_config_d):
        url = self.config_d["url"]
        auth = None
        if "basic_auth" in self.config_d:
            auth = (self.config_d["basic_auth"]["login"],
                    self.config_d["basic_auth"]["password"])
        headers = {'Accept': 'application/json'}
        headers.update(self.config_d.get("headers", {}))
        r = requests.post(url,
                          auth=auth,
                          headers=headers,
                          data=json.dumps(event.serialize()))
        r.raise_for_status()

import json
import requests
from .base import BaseAction

API_BASE_URL = "https://api.github.com"


class Action(BaseAction):
    def trigger(self, event, probe, action_config_d):
        action_config_d = action_config_d or {}
        url = "%s/repos/%s/issues" % (API_BASE_URL, self.config_d["repository"])
        args = {"title": event.get_notification_subject(probe),
                "body": event.get_notification_body(probe)}

        if "assignee" in self.config_d:
            args["assignee"] = self.config_d["assignee"]
        if "labels" in action_config_d:
            args["labels"] = action_config_d["labels"]

        r = requests.post(url,
                          auth=(self.config_d["user"], self.config_d["access_token"]),
                          headers={'Accept': "application/vnd.github.v3+json"}, data=json.dumps(args)
                          )
        r.raise_for_status()

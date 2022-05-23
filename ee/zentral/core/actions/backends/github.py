import json
from django import forms
import requests
from .base import BaseAction, BaseActionForm

API_BASE_URL = "https://api.github.com"


class ActionForm(BaseActionForm):
    assignees = forms.MultipleChoiceField(required=False, choices=[])
    labels = forms.CharField(help_text=("A list of comma separated label names. "
                                        "Example: bug,ui,@high"),
                             required=False)

    def get_assignees_choices(self):
        # TODO: cache ?
        url = "{}/repos/{}/assignees".format(API_BASE_URL,
                                             self.config_d["repository"])
        r = requests.get(url,
                         auth=(self.config_d["user"], self.config_d["access_token"]),
                         headers={'Accept': "application/vnd.github.v3+json"})
        r.raise_for_status()
        return [(a["login"], a["login"]) for a in r.json()]

    def __init__(self, *args, **kwargs):
        super(ActionForm, self).__init__(*args, **kwargs)
        self.fields["assignees"].choices = self.get_assignees_choices()


class Action(BaseAction):
    action_form_class = ActionForm

    def trigger(self, event, probe, action_config_d):
        action_config_d = action_config_d or {}
        url = "%s/repos/%s/issues" % (API_BASE_URL, self.config_d["repository"])
        args = {"title": event.get_notification_subject(probe),
                "body": event.get_notification_body(probe)}

        assignees = self.config_d.get("assignees",
                                      action_config_d.get("assignees", []))
        if assignees:
            args["assignees"] = assignees
        if "labels" in action_config_d:
            args["labels"] = action_config_d["labels"]

        r = requests.post(url,
                          auth=(self.config_d["user"], self.config_d["access_token"]),
                          headers={'Accept': "application/vnd.github.v3+json"}, data=json.dumps(args)
                          )
        r.raise_for_status()

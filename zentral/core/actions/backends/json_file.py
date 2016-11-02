from datetime import datetime
import json
import os
from django import forms
from .base import BaseAction, BaseActionForm


class ActionForm(BaseActionForm):
    sub_dir = forms.CharField(label="Sub dir", required=False)

    def __init__(self, *args, **kwargs):
        super(ActionForm, self).__init__(*args, **kwargs)
        self.fields["sub_dir"].help_text = ("sub dir relative path in '{}'. "
                                            "Can be left empty.").format(self.config_d["local_dir"])


class Action(BaseAction):
    action_form_class = ActionForm

    def trigger(self, event, probe, action_config_d):
        action_config_d = action_config_d or {}
        local_dir = self.config_d['local_dir']
        sub_dir = action_config_d.get('sub_dir', None)
        if sub_dir:
            local_dir = os.path.join(local_dir, sub_dir)
        if not os.path.exists(local_dir):
            os.makedirs(local_dir)
        file_path = os.path.join(local_dir, datetime.now().isoformat())
        with open(file_path, 'w') as f:
            json.dump({'subject': event.get_notification_subject(probe),
                       'body': event.get_notification_body(probe)},
                      f, sort_keys=True, indent=4)

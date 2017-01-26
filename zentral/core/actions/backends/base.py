from django import forms
from zentral.conf import contact_groups


class BaseActionForm(forms.Form):
    def __init__(self, *args, **kwargs):
        self.config_d = kwargs.pop("config_d")
        super(BaseActionForm, self).__init__(*args, **kwargs)

    def get_action_config_d(self):
        return {k: v for k, v in self.cleaned_data.items() if v}


class BaseAction(object):
    action_form_class = BaseActionForm
    probe_config_template_name = "core/probes/_action_probe_config.html"

    def __init__(self, config_d):
        self.name = config_d.pop("action_name")
        self.config_d = config_d

    def can_be_updated(self):
        return self.action_form_class != BaseActionForm

    def get_action_form(self, action_config_d=None):
        args = []
        kwargs = {"config_d": self.config_d}
        if action_config_d is not None:
            args.append(action_config_d)
        return self.action_form_class(*args, **kwargs)

    @staticmethod
    def get_probe_context_action_config_d(action_config_d):
        """prepare a dict for the display of the action_config_d in the probe view"""
        pacd = {}
        for key, val in action_config_d.items():
            if not val:
                continue
            if isinstance(val, list):
                val = ', '.join([str(v) for v in val])
            pacd[key.replace("_", " ")] = val
        return pacd


class ContactGroupForm(BaseActionForm):
    groups = forms.MultipleChoiceField(choices=[], required=True,
                                       help_text="Select one or more configured contact groups")

    def __init__(self, *args, **kwargs):
        super(ContactGroupForm, self).__init__(*args, **kwargs)
        self.fields['groups'].choices = [(g, g) for g in contact_groups]

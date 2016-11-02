from django import forms
from zentral.core.probes.forms import BaseCreateProbeForm
from zentral.utils.forms import validate_sha256
from .probes import SantaProbe, Rule


class RuleForm(forms.Form):
    policy = forms.ChoiceField(choices=Rule.POLICY_CHOICES)
    rule_type = forms.ChoiceField(choices=Rule.RULE_TYPE_CHOICES)
    sha256 = forms.CharField(validators=[validate_sha256])
    custom_msg = forms.CharField(label="Custom message", required=False)

    def get_rule_d(self):
        return {f: v for f, v in self.cleaned_data.items() if v}

    @staticmethod
    def get_initial(rule):
        initial = {}
        for attr in ("policy", "rule_type", "sha256", "custom_msg"):
            value = getattr(rule, attr, None)
            if value:
                initial[attr] = value
        return initial


class CreateProbeForm(BaseCreateProbeForm, RuleForm):
    model = SantaProbe
    field_order = ("name", "custom_msg", "policy", "rule_type", "sha256")

    def get_body(self):
        return {"rules": [self.get_rule_d()]}

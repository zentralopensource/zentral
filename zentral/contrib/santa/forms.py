from django import forms
from zentral.core.probes.forms import BaseCreateProbeForm
from zentral.utils.forms import validate_sha256
from .probes import SantaProbe, Rule


class CertificateSearchForm(forms.Form):
    common_name = forms.CharField(label="Common name", required=False,
                                  widget=forms.TextInput(attrs={"placeholder": "common name"}))


class CollectedApplicationSearchForm(forms.Form):
    name = forms.CharField(label="Name", required=False,
                           widget=forms.TextInput(attrs={"placeholder": "name"}))


class RuleForm(forms.Form):
    policy = forms.ChoiceField(choices=Rule.POLICY_CHOICES)
    rule_type = forms.ChoiceField(choices=Rule.RULE_TYPE_CHOICES)
    sha256 = forms.CharField(validators=[validate_sha256])
    custom_msg = forms.CharField(label="Custom message", required=False)

    def __init__(self, *args, **kwargs):
        collected_app = kwargs.pop("collected_app", None)
        certificate = kwargs.pop("certificate", None)
        super().__init__(*args, **kwargs)
        if collected_app or certificate:
            self.fields["rule_type"].widget.attrs["readonly"] = True
            self.fields["sha256"].widget.attrs["readonly"] = True

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

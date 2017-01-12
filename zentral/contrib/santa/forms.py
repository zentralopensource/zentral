from django import forms
from django.utils.translation import ugettext_lazy as _
from zentral.core.probes.forms import BaseCreateProbeForm
from zentral.utils.api_views import EnrollmentForm
from zentral.utils.forms import validate_sha256
from .osx_package.builder import SantaZentralEnrollPkgBuilder
from .probes import SantaProbe, Rule


class SantaEnrollmentForm(EnrollmentForm):
    mode = forms.ChoiceField(
        label=_("Mode"),
        choices=((SantaZentralEnrollPkgBuilder.MONITOR_MODE, _("Monitor")),
                 (SantaZentralEnrollPkgBuilder.LOCKDOWN_MODE, _("Lockdown"))),
        initial=SantaZentralEnrollPkgBuilder.MONITOR_MODE,
        help_text="In Monitor mode, only blacklisted binaries will be blocked. "
                  "In Lockdown mode, only whitelisted binaries will be allowed to run.")

    def get_build_kwargs(self):
        mode = int(self.cleaned_data.get("mode", SantaZentralEnrollPkgBuilder.MONITOR_MODE))
        return {"mode": mode}


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

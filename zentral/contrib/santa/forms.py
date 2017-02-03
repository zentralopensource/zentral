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
    whitelist_regex = forms.CharField(
        label=_("Whitelist regex"),
        help_text="In Lockdown mode, executables whose paths are a matched by this regex will be allowed to run.",
        required=False
    )
    blacklist_regex = forms.CharField(
        label=_("Blacklist regex"),
        help_text="In Monitor mode, executables whose paths are matched by this regex will be blocked.",
        required=False
    )

    def get_build_kwargs(self):
        mode = int(self.cleaned_data.get("mode", SantaZentralEnrollPkgBuilder.MONITOR_MODE))
        kwargs = {"mode": mode}
        if mode == SantaZentralEnrollPkgBuilder.MONITOR_MODE:
            blacklist_regex = self.cleaned_data.get("blacklist_regex")
            if blacklist_regex:
                kwargs["blacklist_regex"] = blacklist_regex
        elif mode == SantaZentralEnrollPkgBuilder.LOCKDOWN_MODE:
            whitelist_regex = self.cleaned_data.get("whitelist_regex")
            if whitelist_regex:
                kwargs["whitelist_regex"] = whitelist_regex
        return kwargs

    def clean(self):
        cleaned_data = super().clean()
        mode = cleaned_data.get("mode")
        if mode:
            mode = int(mode)
            whitelist_regex = cleaned_data.get("whitelist_regex")
            blacklist_regex = cleaned_data.get("blacklist_regex")
            if mode == SantaZentralEnrollPkgBuilder.LOCKDOWN_MODE and blacklist_regex:
                self.add_error("blacklist_regex",
                               "Can't use a blacklist regex in Lockdown mode.")
            elif mode == SantaZentralEnrollPkgBuilder.MONITOR_MODE and whitelist_regex:
                self.add_error("whitelist_regex",
                               "Can't use a whitelist regex in Monitor mode.")


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

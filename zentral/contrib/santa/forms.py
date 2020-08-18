from django import forms
from zentral.conf import settings
from zentral.core.probes.forms import BaseCreateProbeForm
from zentral.utils.forms import validate_sha256
from .models import Configuration, Enrollment
from .probes import SantaProbe, Rule


class ConfigurationForm(forms.ModelForm):
    class Meta:
        model = Configuration
        fields = '__all__'

    def clean(self):
        cleaned_data = super().clean()

        # no blocked path regex in lockdown mode
        client_mode = cleaned_data.get("client_mode")
        blocked_path_regex = cleaned_data.get("blocked_path_regex")
        if client_mode == Configuration.LOCKDOWN_MODE and blocked_path_regex:
            self.add_error("blocked_path_regex",
                           "Can't use a bloked path regex in Lockdown mode.")

        # client certificate authentication
        client_certificate_auth = cleaned_data.get("client_certificate_auth", False)
        client_auth_certificate_issuer_cn = cleaned_data.get("client_auth_certificate_issuer_cn")
        if client_auth_certificate_issuer_cn and not client_certificate_auth:
            self.add_error("client_certificate_auth",
                           "Needs to be checked to use Client auth certificate issuer CN")
        if (client_certificate_auth or client_auth_certificate_issuer_cn) and \
           "tls_hostname_for_client_cert_auth" not in settings["api"]:
            for field in ("client_certificate_auth", "client_auth_certificate_issuer_cn"):
                self.add_error(
                    field,
                    "The server requiring the client cert for authentication is not configured."
                )
        return cleaned_data


class EnrollmentForm(forms.ModelForm):
    class Meta:
        model = Enrollment
        fields = ("configuration",)

    def __init__(self, *args, **kwargs):
        # meta business unit not used in this enrollment form
        self.meta_business_unit = kwargs.pop("meta_business_unit", None)
        self.configuration = kwargs.pop("configuration", None)
        self.update_for = kwargs.pop("update_for", None)
        self.standalone = kwargs.pop("standalone", False)
        super().__init__(*args, **kwargs)
        # hide configuration dropdown if configuration if fixed
        if self.configuration:
            self.fields["configuration"].widget = forms.HiddenInput()


class CertificateSearchForm(forms.Form):
    query = forms.CharField(required=False,
                            widget=forms.TextInput(attrs={"placeholder": "common name, organization",
                                                          "size": 50}))


class CollectedApplicationSearchForm(forms.Form):
    name = forms.CharField(label="Name", required=False,
                           widget=forms.TextInput(attrs={"placeholder": "name",
                                                         "size": 50}))


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
            self.fields["rule_type"].widget = forms.HiddenInput()
            self.fields["sha256"].widget = forms.HiddenInput()

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

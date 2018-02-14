from django import forms
from zentral.core.probes.forms import BaseCreateProbeForm
from zentral.utils.forms import validate_sha256
from .models import Configuration, Enrollment
from .probes import SantaProbe, Rule
from .releases import Releases


class ConfigurationForm(forms.ModelForm):
    class Meta:
        model = Configuration
        fields = '__all__'

    def clean(self):
        cleaned_data = super().clean()
        client_mode = cleaned_data.get("client_mode")
        blacklist_regex = cleaned_data.get("blacklist_regex")
        if client_mode == Configuration.LOCKDOWN_MODE and blacklist_regex:
            self.add_error("blacklist_regex",
                           "Can't use a blacklist regex in Lockdown mode.")
        return cleaned_data


class EnrollmentForm(forms.ModelForm):
    configuration = forms.ModelChoiceField(queryset=Configuration.objects.all(), required=True)
    santa_release = forms.ChoiceField(
        label="Santa release",
        choices=[],
        initial="",
        help_text="Choose a santa release to be installed by the enrollment package.",
        required=False
    )

    class Meta:
        model = Enrollment
        fields = ("configuration", "santa_release")

    def __init__(self, *args, **kwargs):
        self.configuration = kwargs.pop("configuration", None)
        self.update_for = kwargs.pop("update_for", None)
        self.standalone = kwargs.pop("standalone", False)
        super().__init__(*args, **kwargs)
        # hide configuration dropdown if configuration if fixed
        if self.configuration:
            self.fields["configuration"].widget = forms.HiddenInput()

        # release
        release_field = self.fields["santa_release"]
        if self.update_for:
            release_field.widget = forms.HiddenInput()
        else:
            r = Releases()
            release_choices = [(filename, filename) for filename, _, _, _, _ in r.get_versions()]
            if not self.standalone:
                release_choices.insert(0, ("", "Do not include santa"))
            release_field.choices = release_choices


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

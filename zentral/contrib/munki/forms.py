from django import forms
from zentral.core.probes.forms import BaseCreateProbeForm
from zentral.utils.forms import CommaSeparatedQuotedStringField
from zentral.utils.os_version import make_comparable_os_version
from .compliance_checks import validate_expected_result
from .models import Configuration, Enrollment, PrincipalUserDetectionSource, ScriptCheck
from .probes import MunkiInstallProbe


class PrincipalUserDetectionSourceWidget(forms.CheckboxSelectMultiple):
    def __init__(self, attrs=None, choices=()):
        super().__init__(attrs, choices=PrincipalUserDetectionSource.choices())

    def format_value(self, value):
        if isinstance(value, str) and value:
            value = [v.strip() for v in value.split(",")]
        return super().format_value(value)


class ConfigurationForm(forms.ModelForm):
    class Meta:
        model = Configuration
        fields = "__all__"
        widgets = {
            "principal_user_detection_sources": PrincipalUserDetectionSourceWidget,
            "description": forms.Textarea(attrs={"rows": "2"})
        }


class EnrollmentForm(forms.ModelForm):
    class Meta:
        model = Enrollment
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        self.configuration = kwargs.pop("configuration", None)
        kwargs.pop("enrollment_only", None)
        kwargs.pop("standalone", None)
        super().__init__(*args, **kwargs)
        if self.configuration:
            self.fields["configuration"].widget = forms.HiddenInput()


class ScriptCheckSearchForm(forms.Form):
    template_name = "django/forms/search.html"

    name = forms.CharField(
        label='Name',
        required=False,
        widget=forms.TextInput(
            attrs={"autofocus": True,
                   "size": 32,
                   }
        )
    )
    type = forms.ChoiceField(
        choices=[('', '...')] + ScriptCheck.Type.choices,
        required=False,
    )

    def get_queryset(self):
        qs = ScriptCheck.objects.all()
        name = self.cleaned_data.get("name")
        if name:
            qs = qs.filter(compliance_check__name__icontains=name)
        type = self.cleaned_data.get("type")
        if type:
            qs = qs.filter(type=type)
        return qs.order_by("compliance_check__name")


class ScriptCheckForm(forms.ModelForm):
    class Meta:
        model = ScriptCheck
        fields = ("type", "source", "expected_result",
                  "tags", "arch_amd64", "arch_arm64",
                  "min_os_version", "max_os_version")
        widgets = {
            "expected_result": forms.TextInput
        }

    def clean(self):
        super().clean()
        # expected result type
        script_check_type = self.cleaned_data.get("type")
        expected_result = self.cleaned_data.get("expected_result")
        if script_check_type and expected_result:
            expected_result_valid, error_message = validate_expected_result(script_check_type, expected_result)
            if not expected_result_valid:
                self.add_error("expected_result", error_message)
        # at least one arch
        arch_amd64 = self.cleaned_data.get("arch_amd64")
        arch_arm64 = self.cleaned_data.get("arch_arm64")
        if not arch_amd64 and not arch_arm64:
            msg = "This check has to run on at least one architecture"
            self.add_error("arch_amd64", msg)
            self.add_error("arch_arm64", msg)
        # min / max OS versions
        min_os_version = self.cleaned_data.get("min_os_version")
        comparable_min_os_version = None
        if min_os_version:
            comparable_min_os_version = make_comparable_os_version(min_os_version)
            if comparable_min_os_version == (0, 0, 0):
                self.add_error("min_os_version", "Not a valid OS version")
        max_os_version = self.cleaned_data.get("max_os_version")
        comparable_max_os_version = None
        if max_os_version:
            comparable_max_os_version = make_comparable_os_version(max_os_version)
            if comparable_max_os_version == (0, 0, 0):
                self.add_error("max_os_version", "Not a valid OS version")
        if (
            comparable_min_os_version
            and comparable_max_os_version
            and comparable_max_os_version > (0, 0, 0)
            and comparable_min_os_version > comparable_max_os_version
        ):
            self.add_error("min_os_version", "Should be smaller than the max OS version")


class UpdateInstallProbeForm(forms.Form):
    installed_item_names = CommaSeparatedQuotedStringField(help_text="Comma separated names of the installed items",
                                                           required=False)
    install_types = forms.ChoiceField(choices=(('install,removal', 'install & removal'),
                                               ('install', 'install'),
                                               ('removal', 'removal')),
                                      initial='install',
                                      widget=forms.RadioSelect)
    unattended_installs = forms.ChoiceField(choices=(('', 'yes & no'),
                                                     ('1', 'yes'),
                                                     ('0', 'no')),
                                            widget=forms.RadioSelect,
                                            required=False)

    def get_body(self):
        cleaned_data = self.cleaned_data
        # install types
        body = {'install_types': sorted(cleaned_data['install_types'].split(','))}
        # installed item names
        installed_item_names = cleaned_data.get('installed_item_names')
        if installed_item_names:
            body['installed_item_names'] = installed_item_names
        # unattended installs
        try:
            unattended_installs = bool(int(cleaned_data.get('unattended_installs')))
        except ValueError:
            pass
        else:
            body['unattended_installs'] = unattended_installs
        return body

    @staticmethod
    def get_probe_initial(probe):
        initial = {'installed_item_names': sorted(probe.installed_item_names),
                   'install_types': ','.join(sorted(probe.install_types))}
        if probe.unattended_installs is None:
            initial['unattended_installs'] = ''
        else:
            initial['unattended_installs'] = str(int(probe.unattended_installs))
        return initial


class CreateInstallProbeForm(BaseCreateProbeForm, UpdateInstallProbeForm):
    model = MunkiInstallProbe
    field_order = ("name", "installed_item_names", "unattended_yes", "unattended_no")

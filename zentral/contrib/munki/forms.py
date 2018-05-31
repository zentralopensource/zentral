from django import forms
from zentral.core.probes.forms import BaseCreateProbeForm
from zentral.utils.forms import CommaSeparatedQuotedStringField
from .models import Enrollment
from .probes import MunkiInstallProbe


class EnrollmentForm(forms.ModelForm):
    class Meta:
        model = Enrollment
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        kwargs.pop("update_for", None)
        kwargs.pop("standalone", None)
        super().__init__(*args, **kwargs)


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

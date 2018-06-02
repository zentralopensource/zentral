from django import forms
from django.utils.translation import ugettext_lazy as _
from zentral.utils.filebeat_releases import Releases


class AuditShipperForm(forms.Form):
    release = forms.ChoiceField(
        label=_("Release"),
        choices=[],
        initial="",
        help_text="Choose a filebeat release to be installed with the enrollment package.",
        required=True
    )
    client_certificate_path = forms.CharField(
        label=_("TLS client certificate path"),
        help_text="The local path to the client certificate for filebeat.",
        required=True
    )
    client_certificate_key_path = forms.CharField(
        label=_("TLS client certificate key path"),
        help_text="The local path to the client certificate key for filebeat.",
        required=True
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # TODO: Async or cached to not slow down the web page
        r = Releases()
        choices = []
        for filename, version, created_at, download_url, is_local in r.get_versions():
            choices.append((filename, filename))
        self.fields["release"].choices = choices

    def get_build_kwargs(self):
        kwargs = {}
        for attr in ("release", "client_certificate_path", "client_certificate_key_path"):
            kwargs[attr] = self.cleaned_data[attr]
        return kwargs

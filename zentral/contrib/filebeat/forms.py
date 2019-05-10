from django import forms
from zentral.utils.filebeat_releases import Releases
from .models import Configuration, Enrollment


class ConfigurationForm(forms.ModelForm):
    class Meta:
        model = Configuration
        fields = '__all__'


class EnrollmentForm(forms.ModelForm):
    filebeat_release = forms.ChoiceField(
        label="Filebeat release",
        choices=[],
        initial="",
        help_text="Choose a filebeat release to be installed by the enrollment package.",
        required=False
    )

    class Meta:
        model = Enrollment
        fields = ("configuration", "filebeat_release")

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

        # release
        release_field = self.fields["filebeat_release"]
        if self.update_for:
            release_field.widget = forms.HiddenInput()
        else:
            r = Releases()
            release_choices = [(filename, filename) for filename, _, _, _, _ in r.get_versions()]
            if not self.standalone:
                release_choices.insert(0, ("", "Do not include filebeat"))
            release_field.choices = release_choices

import re
from django import forms
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import BusinessUnit
from .models import JamfInstance, TagConfig


class JamfInstanceForm(forms.ModelForm):
    password = forms.CharField(max_length=256, widget=forms.PasswordInput(render_value=True))

    class Meta:
        model = JamfInstance
        fields = (
            "business_unit",
            "host", "port", "path",
            "user",
            "inventory_apps_shard",
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["business_unit"].queryset = (
            BusinessUnit.objects.filter(source__module="zentral.contrib.inventory")
                                .order_by('meta_business_unit__name')
        )
        self._password = None
        if self.instance.pk:
            self.fields["password"].initial = self.instance.get_password()

    def clean_password(self):
        self._password = self.cleaned_data.pop("password")
        # return temporary invalid password
        return "!" + get_random_string()

    def save(self):
        if self.instance.pk:
            jamf_instance = super().save(commit=False)
            jamf_instance.set_password(self._password)
            jamf_instance.save()  # bump version
        else:
            jamf_instance = super().save()  # commit to get a PK
            jamf_instance.set_password(self._password)
            super(JamfInstance, jamf_instance).save()  # do not bump version
        return jamf_instance


class TagConfigForm(forms.ModelForm):
    class Meta:
        model = TagConfig
        fields = ("source", "taxonomy", "regex", "replacement")

    def clean_regex(self):
        regex = self.cleaned_data["regex"]
        if regex:
            try:
                re.compile(regex)
            except re.error:
                raise forms.ValidationError("Not a valid regex")
        return regex

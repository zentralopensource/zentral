import re
from django import forms
from zentral.contrib.inventory.models import BusinessUnit
from .models import JamfInstance, TagConfig


class JamfInstanceForm(forms.ModelForm):
    class Meta:
        model = JamfInstance
        fields = (
            "business_unit",
            "host", "port", "path",
            "user", "password",
            "inventory_apps_shard",
        )
        widgets = {
            'password': forms.PasswordInput(render_value=True)
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["business_unit"].queryset = (
            BusinessUnit.objects.filter(source__module="zentral.contrib.inventory")
                                .order_by('meta_business_unit__name')
        )


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

import re
from django import forms
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
            "bearer_token_authentication",
            "inventory_apps_shard",
            "checkin_heartbeat_timeout",
            "inventory_completed_heartbeat_timeout",
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.order_fields([
            "business_unit",
            "host", "port", "path",
            "user", "password",
            "bearer_token_authentication",
            "inventory_apps_shard",
            "checkin_heartbeat_timeout",
            "inventory_completed_heartbeat_timeout",
        ])
        self.fields["business_unit"].queryset = (
            BusinessUnit.objects.filter(source__module="zentral.contrib.inventory")
                                .order_by('meta_business_unit__name')
        )
        if self.instance.pk:
            self.fields["password"].initial = self.instance.get_password()

    def save(self):
        new_instance = self.instance.pk is None
        if new_instance:
            instance = super().save()  # PK needed for the password
        else:
            instance = super().save(commit=False)
        instance.set_password(self.cleaned_data["password"])
        instance.save(bump_version=not new_instance)
        return instance


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

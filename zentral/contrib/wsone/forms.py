from django import forms
from zentral.contrib.inventory.models import BusinessUnit
from .models import Instance


class InstanceForm(forms.ModelForm):
    api_key = forms.CharField(widget=forms.PasswordInput(render_value=True))
    client_secret = forms.CharField(widget=forms.PasswordInput(render_value=True))
    password = forms.CharField(widget=forms.PasswordInput(render_value=True))

    class Meta:
        model = Instance
        fields = (
            "business_unit",
            "server_url",
            "client_id", "token_url",
            "username",
            "excluded_groups",
        )
        widgets = {
            "client_id": forms.TextInput,
            "username": forms.TextInput,
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.order_fields([
            "business_unit",
            "server_url", "api_key",
            "client_id", "client_secret", "token_url",
            "username", "password",
            "excluded_groups",
        ])
        self.fields["business_unit"].queryset = (
            BusinessUnit.objects.filter(source__module="zentral.contrib.inventory")
                                .order_by('meta_business_unit__name')
        )
        if self.instance.pk:
            self.fields["api_key"].initial = self.instance.get_api_key()
            self.fields["client_secret"].initial = self.instance.get_client_secret()
            self.fields["password"].initial = self.instance.get_password()

    def save(self):
        new_instance = self.instance.pk is None
        if new_instance:
            instance = super().save()  # PK needed for the secrets
        else:
            instance = super().save(commit=False)
        instance.set_api_key(self.cleaned_data["api_key"])
        instance.set_client_secret(self.cleaned_data["client_secret"])
        instance.set_password(self.cleaned_data["password"])
        instance.save(bump_version=not new_instance)
        return instance

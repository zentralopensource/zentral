from django import forms
from zentral.contrib.inventory.models import BusinessUnit
from .models import AirwatchInstance
from .api_client import APIClient, APIClientError


class AirwatchInstanceForm(forms.ModelForm):
    class Meta:
        model = AirwatchInstance
        fields = ("business_unit", "host", "port", "path", "user", "password", "aw_tenant_code")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["business_unit"].queryset = (
            BusinessUnit.objects.filter(source__module="zentral.contrib.inventory")
                                .order_by('meta_business_unit__name')
        )

    def clean_aw_tenant_code(self):
        host = self.cleaned_data["host"]
        port = self.cleaned_data["port"]
        path = self.cleaned_data["path"]
        user = self.cleaned_data["user"]
        password = self.cleaned_data["password"]
        aw_tenant_code = self.cleaned_data["aw_tenant_code"]
        try:
            api_client = APIClient(host, port, path, user, password, aw_tenant_code)
            account = api_client.get_account()
        except APIClientError as e:
            if e.status_code == 401:
                msg = "Invalid API key"
            else:
                msg = "API Error"
            raise forms.ValidationError(msg)
        return aw_tenant_code

    def save(self, *args, **kwargs):
        airwatch_instance = super().save(commit=False)
        airwatch_instance.save()
        return airwatch_instance

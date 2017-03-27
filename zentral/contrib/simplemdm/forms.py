from django import forms
from zentral.contrib.inventory.models import BusinessUnit
from .models import SimpleMDMInstance
from .api_client import APIClient, APIClientError


class SimpleMDMInstanceForm(forms.ModelForm):
    class Meta:
        model = SimpleMDMInstance
        fields = ("business_unit", "api_key")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["business_unit"].queryset = (
            BusinessUnit.objects.filter(source__module="zentral.contrib.inventory")
                                .order_by('meta_business_unit__name')
        )

    def clean_api_key(self):
        api_key = self.cleaned_data["api_key"]
        if api_key:
            api_client = APIClient(api_key)
            try:
                account = api_client.get_account()
            except APIClientError as e:
                if e.status_code == 401:
                    msg = "Invalid API key"
                else:
                    msg = "API Error"
                raise forms.ValidationError(msg)
            else:
                self.account_name = account["name"]
        return api_key

    def save(self, *args, **kwargs):
        simplemdm_instance = super().save(commit=False)
        simplemdm_instance.account_name = self.account_name
        simplemdm_instance.save()
        return simplemdm_instance

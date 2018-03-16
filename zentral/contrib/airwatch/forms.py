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

    def save(self, *args, **kwargs):
        airwatch_instance = super().save(commit=False)
        airwatch_instance.save()
        return airwatch_instance

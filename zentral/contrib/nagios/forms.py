from django import forms
from zentral.contrib.inventory.models import BusinessUnit
from .models import NagiosInstance


class NagiosInstanceForm(forms.ModelForm):
    class Meta:
        model = NagiosInstance
        fields = ("business_unit", "url")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["business_unit"].queryset = (
            BusinessUnit.objects.filter(source__module="zentral.contrib.inventory")
                                .order_by('meta_business_unit__name')
        )

from django import forms
from zentral.contrib.inventory.models import BusinessUnit
from .models import JamfInstance


class JamfInstanceForm(forms.ModelForm):
    class Meta:
        model = JamfInstance
        fields = ("business_unit", "host", "port", "path", "user", "password")
        widgets = {
            'password': forms.PasswordInput(render_value=True)
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["business_unit"].queryset = (
            BusinessUnit.objects.filter(source__module="zentral.contrib.inventory")
                                .order_by('meta_business_unit__name')
        )

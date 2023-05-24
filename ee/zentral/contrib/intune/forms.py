from django import forms
from zentral.contrib.inventory.models import BusinessUnit
from .models import Tenant


class TenantForm(forms.ModelForm):
    client_secret = forms.CharField(widget=forms.PasswordInput(render_value=True))

    class Meta:
        model = Tenant
        fields = (
            "business_unit",
            "name",
            "description",
            "tenant_id",
            "client_id",
            "client_secret",
        )
        widgets = {
            "client_id": forms.TextInput,
            "name": forms.TextInput,
            "tenant_id": forms.TextInput,
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.order_fields([
            "business_unit",
            "name", "description",
            "tenant_id", "client_id",
            "client_secret",
        ])
        self.fields["business_unit"].queryset = (
            BusinessUnit.objects.filter(source__module="zentral.contrib.inventory")
                                .order_by('meta_business_unit__name')
        )
        if self.instance.pk:
            self.fields["client_secret"].initial = self.instance.get_client_secret()

    def save(self):
        new_tenant = self.instance.pk is None
        if new_tenant:
            tenant = super().save()
        else:
            tenant = super().save(commit=False)
        tenant.set_client_secret(self.cleaned_data["client_secret"])
        tenant.save()
        return tenant

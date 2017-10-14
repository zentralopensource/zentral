from django import forms
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from .models import EnrolledDevice, OTAEnrollment, PushCertificate
from .pkcs12 import load_push_certificate


class OTAEnrollmentForm(forms.ModelForm):
    class Meta:
        model = OTAEnrollment
        fields = ("name",)


class OTAEnrollmentSecretForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["meta_business_unit"].queryset = MetaBusinessUnit.objects.filter(
            metabusinessunitpushcertificate__isnull=False
        )

    class Meta:
        model = EnrollmentSecret
        fields = ("meta_business_unit", "tags", "serial_numbers", "udids", "quota")


class PushCertificateForm(forms.ModelForm):
    certificate_file = forms.FileField(required=True)
    password = forms.CharField(widget=forms.PasswordInput, required=False)

    class Meta:
        model = PushCertificate
        fields = ("name",)

    def clean(self):
        cleaned_data = super().clean()
        certificate_file = cleaned_data.pop("certificate_file", None)
        password = cleaned_data.pop("password", None)
        if certificate_file:
            try:
                push_certificate_d = load_push_certificate(certificate_file.read(),
                                                           password)
            except:
                raise forms.ValidationError("Could not process push certificate")
            else:
                cleaned_data.update(push_certificate_d)
        return cleaned_data

    def _post_clean(self):
        # Hack, to add the computed fields
        super()._post_clean()
        for key, val in self.cleaned_data.items():
            setattr(self.instance, key, val)


class EnrolledDeviceSearchForm(forms.Form):
    serial_number = forms.CharField(label="serial number", required=False,
                                    widget=forms.TextInput(attrs={"placeholder": "serial number"}))

    def is_initial(self):
        return not {k: v for k, v in self.cleaned_data.items() if v}

    def search_qs(self):
        qs = EnrolledDevice.objects.all()
        serial_number = self.cleaned_data.get("serial_number")
        if serial_number:
            qs = qs.filter(serial_number__icontains=serial_number)
        return qs

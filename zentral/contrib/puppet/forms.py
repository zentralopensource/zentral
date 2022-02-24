from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django import forms
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import BusinessUnit
from .models import Instance


class InstanceForm(forms.ModelForm):
    rbac_token_auth = forms.BooleanField(
        label="Use PE RBAC token authentication",
        required=False
    )
    rbac_token = forms.CharField(
        label="PE RBAC token",
        required=False,
        widget=forms.PasswordInput(render_value=True),
        help_text="Puppet Enterprise RBAC token to authenticate with PuppetDB"
    )
    client_certificate_auth = forms.BooleanField(
        label="Use client certificate authentication",
        required=False
    )
    key = forms.CharField(
        label="Client key",
        required=False,
        widget=forms.Textarea(),
        help_text="Client key (PEM) to authenticate with PuppetDB"
    )
    key_password = forms.CharField(
        label="Client key password",
        widget=forms.PasswordInput(render_value=True),
        required=False,
        help_text="Optional client key password"
    )

    class Meta:
        model = Instance
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.order_fields([
            "business_unit",
            "url", "ca_chain",
            "rbac_token_auth", "rbac_token",
            "client_certificate_auth", "cert", "key", "key_password",
            "timeout",
            "group_fact_keys", "extra_fact_keys",
            "puppetboard_url", "deb_packages_shard", "programs_shard"
        ])
        self.fields["business_unit"].queryset = (
            BusinessUnit.objects.filter(source__module="zentral.contrib.inventory")
                                .order_by('meta_business_unit__name')
        )
        if self.instance.pk:
            if self.instance.cert:
                self.fields["rbac_token_auth"].label = "Switch to PE RBAC token authentication"
                self.fields["client_certificate_auth"].label = "Update client certificate"
            else:
                self.fields["rbac_token_auth"].label = "Update RBAC token"
                self.fields["client_certificate_auth"].label = "Switch to client certificate authentication"

    def clean(self):
        super().clean()
        rbac_token_auth = self.cleaned_data.get("rbac_token_auth")
        client_certificate_auth = self.cleaned_data.get("client_certificate_auth")
        if not self.instance.pk and not rbac_token_auth and not client_certificate_auth:
            msg = "RBAC token or client certificate authentication is required"
            for field in ("rbac_token_auth", "client_certificate_auth"):
                self.add_error(field, msg)
        else:
            if rbac_token_auth and client_certificate_auth:
                # should never happen. JS GUI error?
                msg = "RBAC token and client certificate authentication are mutually exclusive"
                for field in ("rbac_token_auth", "client_certificate_auth"):
                    self.add_error(field, msg)
            elif rbac_token_auth:
                self.cleaned_data["cert"] = ""
                self.cleaned_data["key"] = ""
                rbac_token = self.cleaned_data.get("rbac_token")
                if not rbac_token:
                    self.add_error("rbac_token", "Required")
            elif client_certificate_auth:
                self.cleaned_data["rbac_token"] = ""
                cert = self.cleaned_data.get("cert")
                if not cert:
                    self.add_error("cert", "Required")
                else:
                    try:
                        x509.load_pem_x509_certificate(cert.encode("ascii"))
                    except Exception:
                        self.add_error("cert", "Cannot load PEM certificate")
                        raise forms.ValidationError("Cannot load PEM certificate")
                key = self.cleaned_data.get("key")
                if not key:
                    self.add_error("key", "Required")
                else:
                    key_password = self.cleaned_data.get("key_password") or None
                    try:
                        loaded_key = serialization.load_pem_private_key(key.encode("ascii"), password=key_password)
                    except Exception:
                        self.add_error("key", "Cannot load PEM private key")
                    else:
                        self.cleaned_data["key"] = loaded_key.private_bytes(
                            serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()
                        ).decode("ascii")
        return self.cleaned_data

    def save(self):
        new_instance = self.instance.pk is None
        if new_instance:
            instance = super().save()  # PK needed for the secrets
            instance.set_report_processor_token(get_random_string(67))
        else:
            instance = super().save(commit=False)
        if any(self.cleaned_data.get(k) for k in ("rbac_token_auth", "client_certificate_auth")):
            instance.set_rbac_token(self.cleaned_data["rbac_token"])
            instance.set_key(self.cleaned_data["key"])
        instance.save()
        return instance

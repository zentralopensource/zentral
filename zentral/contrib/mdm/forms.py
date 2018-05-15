from django import forms
from django.db import connection
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from .dep import decrypt_dep_token
from .dep_client import DEPClient
from .models import (DEPDevice, DEPOrganization, DEPProfile, DEPToken, DEPVirtualServer,
                     OTAEnrollment, PushCertificate)
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


class DeviceSearchForm(forms.Form):
    serial_number = forms.CharField(label="serial number", required=False,
                                    widget=forms.TextInput(attrs={"placeholder": "serial number",
                                                                  "autofocus": True}))

    def is_initial(self):
        return not {k: v for k, v in self.cleaned_data.items() if v}

    def build_query(self):
        query = (
            "WITH devices AS ("

            "SELECT serial_number, NULL AS product, udid AS udid, checkout_at, created_at, updated_at "
            "FROM mdm_enrolleddevice "

            "UNION "

            "SELECT sec.serial_numbers[1], sess.product, sec.udids[1], NULL, sess.created_at, sess.updated_at "
            "FROM mdm_depenrollmentsession as sess "
            "JOIN inventory_enrollmentsecret as sec ON (sec.id = sess.enrollment_secret_id) "

            "UNION "

            "SELECT sec.serial_numbers[1], sess.product, sec.udids[1], NULL, sess.created_at, sess.updated_at "
            "FROM mdm_otaenrollmentsession as sess "
            "JOIN inventory_enrollmentsecret as sec ON (sec.id = sess.enrollment_secret_id) "

            "UNION "

            "SELECT serial_number, NULL, NULL, NULL, created_at, updated_at "
            "FROM mdm_depdevice"

            ") SELECT serial_number, max(product) AS product, array_agg(DISTINCT udid) AS udids, "
            "max(checkout_at) AS checkout_at, min(created_at) AS created_at, max(updated_at) AS updated_at "
            "FROM devices "
        )
        args = []

        # serial number ?
        serial_number = self.cleaned_data.get("serial_number")
        if serial_number:
            query = "{} WHERE serial_number LIKE UPPER(%s) ".format(query)
            args.append("%{}%".format(connection.ops.prep_for_like_query(serial_number)))

        # group by and order
        query = "{} GROUP BY serial_number ORDER BY max(updated_at) DESC;".format(query)

        return query, args

    def fetch_devices(self):
        query, args = self.build_query()
        with connection.cursor() as cursor:
            cursor.execute(query, args)
            attributes = [col.name for col in cursor.description]
            for row in cursor.fetchall():
                device = dict(zip(attributes, row))
                device["udids"] = sorted(udid for udid in device["udids"] if udid)
                yield device


class EncryptedDEPTokenForm(forms.ModelForm):
    encrypted_token = forms.FileField(label="Server token", required=False)

    class Meta:
        model = DEPToken
        fields = []

    def clean(self):
        encrypted_token = self.cleaned_data["encrypted_token"]
        if encrypted_token:
            payload = encrypted_token.read()
            try:
                data = decrypt_dep_token(self.instance, payload)
                kwargs = {k: data.get(k) for k in ("consumer_key", "consumer_secret",
                                                   "access_token", "access_secret")}
                account_d = DEPClient(**kwargs).get_account()
            except:
                self.add_error("encrypted_token", "Could not read or use encrypted token")
            else:
                self.cleaned_data["decrypted_dep_token"] = data
                self.cleaned_data["account"] = account_d
        else:
            self.add_error("encrypted_token", "This field is mandatory")
        return self.cleaned_data

    def save(self, *args, **kwargs):
        # token
        kwargs["commit"] = False
        dep_token = super().save(*args, **kwargs)
        for k, v in self.cleaned_data["decrypted_dep_token"].items():
            setattr(dep_token, k, v)
        dep_token.save()

        account_d = self.cleaned_data["account"]

        # organization
        organization, _ = DEPOrganization.objects.update_or_create(
            identifier=account_d.pop("org_id"),
            defaults={"name": account_d.pop("org_name"),
                      "admin_id": account_d.pop("admin_id"),
                      "email": account_d.pop("org_email"),
                      "phone": account_d.pop("org_phone"),
                      "address": account_d.pop("org_address"),
                      "type": account_d.pop("org_type"),
                      "version": account_d.pop("org_version")}
        )

        # virtual server
        account_d = self.cleaned_data["account"]
        server_uuid = account_d.pop("server_uuid")
        defaults = {"name": account_d["server_name"],
                    "organization": organization,
                    "token": dep_token}
        try:
            virtual_server = DEPVirtualServer.objects.get(uuid=server_uuid)
        except DEPVirtualServer.DoesNotExist:
            virtual_server = DEPVirtualServer.objects.create(uuid=server_uuid, **defaults)
        else:
            # we do not use update_or_create to be able to remove the old dep token
            old_token = virtual_server.token
            for attr, val in defaults.items():
                setattr(virtual_server, attr, val)
            virtual_server.save()
            if old_token and old_token != dep_token:
                old_token.delete()

        return dep_token


class DEPProfileForm(forms.ModelForm):
    meta_business_unit = forms.ModelChoiceField(
        label="Business unit",
        queryset=MetaBusinessUnit.objects.available_for_api_enrollment(),
        required=True
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for pane, initial in self.Meta.model.SKIPPABLE_SETUP_PANES:
            if self.instance.pk:
                initial = pane in self.instance.skip_setup_items
            self.fields[pane] = forms.BooleanField(label="Skip {} pane".format(pane), initial=initial, required=False)

    class Meta:
        model = DEPProfile
        fields = "__all__"

    def clean(self):
        super().clean()
        skip_setup_items = []
        for pane, initial in self.Meta.model.SKIPPABLE_SETUP_PANES:
            if self.cleaned_data.get(pane, False):
                skip_setup_items.append(pane)
        self.cleaned_data['skip_setup_items'] = skip_setup_items

    def save(self, *args, **kwargs):
        commit = kwargs.pop("commit", True)
        kwargs["commit"] = False
        dep_profile = super().save(**kwargs)
        dep_profile.skip_setup_items = self.cleaned_data["skip_setup_items"]
        dep_profile.enrollment_secret = EnrollmentSecret.objects.create(
            meta_business_unit=self.cleaned_data["meta_business_unit"]
        )
        if commit:
            dep_profile.save()
        return dep_profile


class AssignDEPDeviceProfileForm(forms.ModelForm):
    class Meta:
        model = DEPDevice
        fields = ("profile",)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            profile_f = self.fields["profile"]
            profile_f.queryset = profile_f.queryset.filter(virtual_server=self.instance.virtual_server)

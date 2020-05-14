import plistlib
from django import forms
from django.db import connection
from realms.utils import build_password_hash_dict
from zentral.contrib.inventory.models import MetaMachine
from .dep import decrypt_dep_token
from .dep_client import DEPClient
from .models import (DEPDevice, DEPOrganization, DEPProfile, DEPToken, DEPVirtualServer,
                     OTAEnrollment, PushCertificate, MetaBusinessUnitPushCertificate,
                     ConfigurationProfile)
from .pkcs12 import load_push_certificate


class OTAEnrollmentForm(forms.ModelForm):
    class Meta:
        model = OTAEnrollment
        fields = ("name", "realm")


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
            except Exception:
                raise forms.ValidationError("Could not process push certificate")
            else:
                cleaned_data.update(push_certificate_d)
        return cleaned_data

    def _post_clean(self):
        # Hack, to add the computed fields
        super()._post_clean()
        for key, val in self.cleaned_data.items():
            setattr(self.instance, key, val)


class AddPushCertificateBusinessUnitForm(forms.ModelForm):
    class Meta:
        model = MetaBusinessUnitPushCertificate
        fields = ('meta_business_unit',)

    def __init__(self, *args, **kwargs):
        push_certificate = kwargs.pop("push_certificate")
        super().__init__(*args, **kwargs)
        mbu_f = self.fields["meta_business_unit"]
        mbu_id_list = [mbupc.meta_business_unit_id
                       for mbupc in push_certificate.metabusinessunitpushcertificate_set.all()]
        mbu_f.queryset = mbu_f.queryset.exclude(pk__in=mbu_id_list)


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
            query = "{} WHERE UPPER(serial_number) LIKE UPPER(%s) ".format(query)
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
                device["urlsafe_serial_number"] = MetaMachine(device["serial_number"]).get_urlsafe_serial_number()
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
            except Exception:
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


class CreateDEPProfileForm(forms.ModelForm):
    admin_password = forms.CharField(required=False, widget=forms.PasswordInput)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        field_order = [
            "virtual_server", "name",
            "allow_pairing", "is_supervised", "is_mandatory", "is_mdm_removable",
            "await_device_configured", "auto_advance_setup",
            "support_phone_number", "support_email_address",
            "org_magic", "department", "include_tls_certificates"
        ]
        for pane, initial in self.Meta.model.SKIPPABLE_SETUP_PANES:
            if self.instance.pk:
                initial = pane in self.instance.skip_setup_items
            self.fields[pane] = forms.BooleanField(label="Skip {} pane".format(pane), initial=initial, required=False)
            field_order.append(pane)
        field_order.extend(["realm", "use_realm_user", "realm_user_is_admin",
                            "admin_full_name", "admin_short_name", "admin_password"])
        self.order_fields(field_order)

    class Meta:
        model = DEPProfile
        fields = "__all__"

    def clean_is_mdm_removable(self):
        is_mdm_removable = self.cleaned_data.get("is_mdm_removable")
        is_supervised = self.cleaned_data.get("is_supervised")
        if not is_mdm_removable and not is_supervised:
            raise forms.ValidationError("Can only be set to False if 'Is supervised' is set to True")
        return is_mdm_removable

    def clean_use_realm_user(self):
        realm = self.cleaned_data.get("realm")
        use_realm_user = self.cleaned_data.get("use_realm_user")
        if use_realm_user and not realm:
            raise forms.ValidationError("This option is only valid if a 'realm' is selected")
        return use_realm_user

    def clean_realm_user_is_admin(self):
        use_realm_user = self.cleaned_data.get("use_realm_user")
        realm_user_is_admin = self.cleaned_data.get("realm_user_is_admin")
        if realm_user_is_admin and not use_realm_user:
            raise forms.ValidationError("This option is only valid if the 'use realm user' option is ticked too")
        return realm_user_is_admin

    def clean_admin_password(self):
        password = self.cleaned_data.get("admin_password")
        if password:
            self.cleaned_data["admin_password_hash"] = build_password_hash_dict(password)

    def admin_info_incomplete(self):
        return len([attr for attr in (
                        self.cleaned_data.get(i)
                        for i in ("admin_full_name", "admin_short_name", "admin_password_hash")
                    ) if attr]) in (1, 2)

    def clean(self):
        super().clean()
        skip_setup_items = []
        for pane, initial in self.Meta.model.SKIPPABLE_SETUP_PANES:
            if self.cleaned_data.get(pane, False):
                skip_setup_items.append(pane)
        if self.admin_info_incomplete():
            raise forms.ValidationError("Admin information incomplete")
        self.cleaned_data['skip_setup_items'] = skip_setup_items

    def save(self, *args, **kwargs):
        commit = kwargs.pop("commit", True)
        kwargs["commit"] = False
        dep_profile = super().save(**kwargs)
        dep_profile.skip_setup_items = self.cleaned_data["skip_setup_items"]
        dep_profile.admin_password_hash = self.cleaned_data.get("admin_password_hash")
        if commit:
            dep_profile.save()
        return dep_profile


class UpdateDEPProfileForm(CreateDEPProfileForm):
    class Meta:
        model = DEPProfile
        exclude = ("virtual_server",)

    def clean_admin_password(self):
        password = self.cleaned_data.get("admin_password")
        if password:
            self.cleaned_data["admin_password_hash"] = build_password_hash_dict(password)
        else:
            self.cleaned_data["admin_password_hash"] = self.instance.admin_password_hash


class AssignDEPDeviceProfileForm(forms.ModelForm):
    class Meta:
        model = DEPDevice
        fields = ("profile",)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            profile_f = self.fields["profile"]
            profile_f.queryset = profile_f.queryset.filter(virtual_server=self.instance.virtual_server)


class UploadConfigurationProfileForm(forms.Form):
    source_file = forms.FileField(required=True,
                                  help_text="configuration profile file (.mobileconfig)")

    def __init__(self, *args, **kwargs):
        self.meta_business_unit = kwargs.pop("meta_business_unit")
        super().__init__(*args, **kwargs)

    def clean(self):
        source_file = self.cleaned_data.get("source_file")
        if source_file:
            try:
                source = plistlib.load(source_file)
            except Exception:
                raise forms.ValidationError("This file is not a plist.")
            self.cleaned_data["source"] = source
            try:
                self.cleaned_data["source_payload_identifier"] = source["PayloadIdentifier"]
            except KeyError:
                raise forms.ValidationError("Missing PayloadIdentifier")

            for source_key, obj_key in (("PayloadDisplayName", "payload_display_name"),
                                        ("PayloadDescription", "payload_description")):
                self.cleaned_data[obj_key] = source.get(source_key) or ""
            return self.cleaned_data

    def save(self):
        cleaned_data = self.cleaned_data
        source_payload_identifier = cleaned_data["source_payload_identifier"]
        configuration_profile, _ = ConfigurationProfile.objects.update_or_create(
            meta_business_unit=self.meta_business_unit,
            source_payload_identifier=source_payload_identifier,
            defaults={"source": cleaned_data["source"],
                      "payload_display_name": cleaned_data["payload_display_name"],
                      "payload_description": cleaned_data["payload_description"],
                      "trashed_at": None}
        )
        return configuration_profile

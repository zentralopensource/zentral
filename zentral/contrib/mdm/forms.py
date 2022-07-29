import plistlib
from django import forms
from django.db.models import Q
from realms.utils import build_password_hash_dict
from .app_manifest import build_enterprise_app_manifest
from .crypto import load_push_certificate_and_key
from .declarations import update_blueprint_declaration_items
from .dep import decrypt_dep_token
from .dep_client import DEPClient
from .models import (Artifact, ArtifactType, ArtifactVersion, BlueprintArtifact, Channel,
                     DEPDevice, DEPOrganization, DEPEnrollment, DEPToken, DEPVirtualServer,
                     EnrolledDevice, EnterpriseApp, Platform,
                     SCEPConfig,
                     OTAEnrollment, UserEnrollment, PushCertificate,
                     Profile)


class OTAEnrollmentForm(forms.ModelForm):
    class Meta:
        model = OTAEnrollment
        fields = ("name", "realm", "push_certificate", "scep_config", "blueprint")


class UserEnrollmentForm(forms.ModelForm):
    class Meta:
        model = UserEnrollment
        fields = ("name", "realm", "push_certificate", "scep_config", "blueprint")


class UserEnrollmentEnrollForm(forms.Form):
    managed_apple_id = forms.EmailField(label="Email", required=True)


class PushCertificateForm(forms.ModelForm):
    certificate_file = forms.FileField(required=True)
    key_file = forms.FileField(required=True)
    key_password = forms.CharField(widget=forms.PasswordInput, required=False)

    class Meta:
        model = PushCertificate
        fields = ("name",)

    def clean(self):
        cleaned_data = super().clean()
        certificate_file = cleaned_data.pop("certificate_file", None)
        key_file = cleaned_data.pop("key_file", None)
        key_password = cleaned_data.pop("key_password", None)
        if certificate_file and key_file:
            try:
                push_certificate_d = load_push_certificate_and_key(
                    certificate_file.read(),
                    key_file.read(), key_password
                )
            except ValueError as e:
                raise forms.ValidationError(str(e))
            except Exception:
                raise forms.ValidationError("Could not load certificate or key file")
            if self.instance.topic and push_certificate_d["topic"] != self.instance.topic:
                raise forms.ValidationError("The new certificate has a different topic")
            for key, val in push_certificate_d.items():
                setattr(self.instance, key, val)
        return cleaned_data


class EnrolledDeviceSearchForm(forms.Form):
    q = forms.CharField(required=False,
                        widget=forms.TextInput(attrs={"placeholder": "Serial number, UDID",
                                                      "autofocus": True}))

    def get_queryset(self):
        qs = EnrolledDevice.objects.all().order_by("-updated_at")
        q = self.cleaned_data.get("q")
        if q:
            qs = qs.filter(Q(serial_number__icontains=q) | Q(udid__icontains=q))
        return qs


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
            DEPVirtualServer.objects.create(uuid=server_uuid, **defaults)
        else:
            # we do not use update_or_create to be able to remove the old dep token
            old_token = virtual_server.token
            for attr, val in defaults.items():
                setattr(virtual_server, attr, val)
            virtual_server.save()
            if old_token and old_token != dep_token:
                old_token.delete()

        return dep_token


class CreateDEPEnrollmentForm(forms.ModelForm):
    admin_password = forms.CharField(required=False, widget=forms.PasswordInput)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        field_order = [
            "push_certificate", "scep_config", "blueprint",
            "virtual_server", "name",
            "allow_pairing", "is_supervised", "is_mandatory", "is_mdm_removable", "is_multi_user",
            "await_device_configured", "auto_advance_setup", "include_tls_certificates",
            "support_phone_number", "support_email_address",
            "org_magic", "department", "language", "region"
        ]
        for pane, initial in self.Meta.model.SKIPPABLE_SETUP_PANES:
            if self.instance.pk:
                initial = pane in self.instance.skip_setup_items
            self.fields[pane] = forms.BooleanField(label="Skip {} pane".format(pane), initial=initial, required=False)
            field_order.append(pane)
        field_order.extend(["realm", "use_realm_user", "realm_user_is_admin",
                            "admin_full_name", "admin_short_name", "admin_password"])
        self.order_fields(field_order)
        self.fields["language"].choices = sorted(self.fields["language"].choices, key=lambda t: (t[1], t[0]))
        self.fields["region"].choices = sorted(self.fields["region"].choices, key=lambda t: (t[1], t[0]))

    class Meta:
        model = DEPEnrollment
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


class UpdateDEPEnrollmentForm(CreateDEPEnrollmentForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["language"].choices = sorted(self.fields["language"].choices, key=lambda t: (t[1], t[0]))
        self.fields["region"].choices = sorted(self.fields["region"].choices, key=lambda t: (t[1], t[0]))

    class Meta:
        model = DEPEnrollment
        exclude = ("virtual_server",)

    def clean_admin_password(self):
        password = self.cleaned_data.get("admin_password")
        if password:
            self.cleaned_data["admin_password_hash"] = build_password_hash_dict(password)
        else:
            self.cleaned_data["admin_password_hash"] = self.instance.admin_password_hash


class AssignDEPDeviceEnrollmentForm(forms.ModelForm):
    class Meta:
        model = DEPDevice
        fields = ("enrollment",)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            profile_f = self.fields["enrollment"]
            profile_f.queryset = profile_f.queryset.filter(virtual_server=self.instance.virtual_server)


class UploadEnterpriseAppForm(forms.Form):
    package = forms.FileField(required=True,
                              help_text="macOS distribution package (.pkg)")

    def clean(self):
        package = self.cleaned_data.get("package")
        if package:
            try:
                title, product_id, product_version, manifest, bundles = build_enterprise_app_manifest(package)
            except Exception as e:
                raise forms.ValidationError(f"Invalid package: {e}")
            if title is None:
                title = product_id
            name = f"{title} - {product_version}"
            if (
                Artifact.objects.exclude(
                    artifactversion__enterprise_app__product_id=product_id,
                    artifactversion__enterprise_app__product_version=product_version
                ).filter(name=name).count()
            ):
                raise forms.ValidationError(
                    "An artifact with the same name but a different product already exists"
                )
            self.cleaned_data["name"] = name
            self.cleaned_data["filename"] = package.name
            self.cleaned_data["product_id"] = product_id
            self.cleaned_data["product_version"] = product_version
            self.cleaned_data["manifest"] = manifest
            self.cleaned_data["bundles"] = bundles
            return self.cleaned_data

    def save(self):
        cleaned_data = self.cleaned_data
        product_id = cleaned_data["product_id"]
        product_version = cleaned_data["product_version"]
        name = cleaned_data.pop("name")
        operation = None
        enterprise_apps = (EnterpriseApp.objects.select_for_update()
                                                .filter(product_id=product_id,
                                                        product_version=product_version)
                                                .select_related("artifact_version__artifact"))
        enterprise_app = enterprise_apps.order_by("-artifact_version__version").first()
        if enterprise_app is None:
            operation = "created"
            artifact = Artifact.objects.create(name=name,
                                               type=ArtifactType.EnterpriseApp.name,
                                               channel=Channel.Device.name,
                                               platforms=[Platform.macOS.name])
            artifact_version = ArtifactVersion.objects.create(artifact=artifact, version=1)
            EnterpriseApp.objects.create(artifact_version=artifact_version, **cleaned_data)
        else:
            artifact = enterprise_app.artifact_version.artifact
            if enterprise_app.manifest != cleaned_data["manifest"]:
                operation = "updated"
                artifact_version = ArtifactVersion.objects.create(artifact=artifact,
                                                                  version=enterprise_app.artifact_version.version + 1)
                EnterpriseApp.objects.create(artifact_version=artifact_version, **cleaned_data)
                artifact.name = name
                artifact.trashed_at = None
                artifact.save()
        return artifact, operation


class UploadProfileForm(forms.Form):
    source_file = forms.FileField(required=True,
                                  help_text="configuration profile file (.mobileconfig)")

    def clean(self):
        source_file = self.cleaned_data.get("source_file")
        if source_file:
            try:
                payload = plistlib.load(source_file)
            except Exception:
                raise forms.ValidationError("This file is not a plist.")
            try:
                self.cleaned_data["payload_identifier"] = payload["PayloadIdentifier"]
            except KeyError:
                raise forms.ValidationError("Missing PayloadIdentifier")
            try:
                self.cleaned_data["payload_uuid"] = payload["PayloadUUID"]
            except KeyError:
                raise forms.ValidationError("Missing PayloadUUID")
            payload_scope = payload.get("PayloadScope", "User")
            if payload_scope == "System":
                self.cleaned_data["channel"] = Channel.Device.value
            elif payload_scope == "User":
                self.cleaned_data["channel"] = Channel.User.value
            else:
                raise forms.ValidationError(f"Unknown PayloadScope: {payload_scope}")
            for payload_key, obj_key in (("PayloadDisplayName", "payload_display_name"),
                                         ("PayloadDescription", "payload_description")):
                self.cleaned_data[obj_key] = payload.get(payload_key) or ""
            name = self.cleaned_data.get("payload_display_name") or self.cleaned_data["payload_uuid"]
            if (
                Artifact.objects.exclude(
                    artifactversion__profile__payload_identifier=self.cleaned_data["payload_identifier"]
                ).filter(name=name).count()
            ):
                raise forms.ValidationError(
                    "An artifact with the same name but a different payload identifier already exists"
                )
            self.cleaned_data["name"] = name
            source_file = self.cleaned_data.pop("source_file")
            source_file.seek(0)
            self.cleaned_data["source"] = source_file.read()
            self.cleaned_data["filename"] = source_file.name
            return self.cleaned_data

    def save(self):
        cleaned_data = self.cleaned_data
        payload_identifier = cleaned_data["payload_identifier"]
        name = cleaned_data.pop("name")
        channel = cleaned_data.pop("channel")
        operation = None
        profiles = (Profile.objects.select_for_update()
                                   .filter(payload_identifier=payload_identifier)
                                   .select_related("artifact_version__artifact"))
        profile = profiles.order_by("-artifact_version__version").first()
        if profile is None:
            operation = "created"
            artifact = Artifact.objects.create(name=name,
                                               type=ArtifactType.Profile.name,
                                               channel=channel,
                                               platforms=Platform.all_values())
            artifact_version = ArtifactVersion.objects.create(artifact=artifact, version=1)
            Profile.objects.create(artifact_version=artifact_version, **cleaned_data)
        else:
            artifact = profile.artifact_version.artifact
            if profile.source.tobytes() != cleaned_data["source"]:
                operation = "updated"
                artifact_version = ArtifactVersion.objects.create(artifact=artifact,
                                                                  version=profile.artifact_version.version + 1)
                Profile.objects.create(artifact_version=artifact_version, **cleaned_data)
                artifact.name = name
                artifact.channel = channel
                artifact.trashed_at = None
                artifact.save()
            elif artifact.trashed_at:
                artifact.trashed_at = None
                artifact.save()
        for blueprint_artifact in artifact.blueprintartifact_set.select_related("blueprint").all():
            update_blueprint_declaration_items(blueprint_artifact.blueprint, commit=True)
        return artifact, operation


class PlatformsWidget(forms.CheckboxSelectMultiple):
    def __init__(self, attrs=None, choices=()):
        super().__init__(attrs, choices=Platform.choices())

    def format_value(self, value):
        if isinstance(value, str) and value:
            value = [v.strip() for v in value.split(",")]
        return super().format_value(value)


class UpdateArtifactForm(forms.ModelForm):
    class Meta:
        model = Artifact
        fields = ("platforms",)
        widgets = {"platforms": PlatformsWidget}


class BlueprintArtifactForm(forms.ModelForm):
    class Meta:
        model = BlueprintArtifact
        fields = ("blueprint", "priority", "install_before_setup_assistant", "auto_update")

    def __init__(self, *args, **kwargs):
        self.artifact = kwargs.pop("artifact")
        super().__init__(*args, **kwargs)
        current_blueprint_pk = None
        if self.instance.pk:
            current_blueprint_pk = self.instance.blueprint.pk
        exluded_bpa_pk = [
            bpa.blueprint.pk for bpa in self.artifact.blueprintartifact_set.all()
            if not bpa.blueprint.pk == current_blueprint_pk
        ]
        bpqs = self.fields["blueprint"].queryset
        bpqs = bpqs.exclude(pk__in=exluded_bpa_pk)
        self.fields["blueprint"].queryset = bpqs

    def save(self, *args, **kwargs):
        self.instance.artifact = self.artifact
        return super().save(*args, **kwargs)


class SCEPConfigForm(forms.ModelForm):
    class Meta:
        model = SCEPConfig
        fields = "__all__"

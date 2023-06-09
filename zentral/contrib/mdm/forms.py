import base64
import hashlib
import json
import logging
import plistlib
from dateutil import parser
from django import forms
from django.db import IntegrityError, transaction
from django.db.models import Count, Q
from realms.utils import build_password_hash_dict
from zentral.contrib.inventory.models import Tag
from .app_manifest import build_enterprise_app_manifest
from .apps_books import AppsBooksClient
from .artifacts import update_blueprint_serialized_artifacts
from .crypto import load_push_certificate_and_key, verify_signed_payload
from .dep import decrypt_dep_token
from .dep_client import DEPClient
from .models import (Artifact, ArtifactVersion, ArtifactVersionTag,
                     Blueprint, BlueprintArtifact, BlueprintArtifactTag, Channel,
                     DEPDevice, DEPOrganization, DEPEnrollment, DEPToken, DEPVirtualServer,
                     EnrolledDevice, EnterpriseApp, Platform,
                     SCEPConfig,
                     OTAEnrollment, UserEnrollment, PushCertificate,
                     Profile, Location, LocationAsset, StoreApp)


logger = logging.getLogger("zentral.contrib.mdm.forms")


class OTAEnrollmentForm(forms.ModelForm):
    class Meta:
        model = OTAEnrollment
        fields = ("name", "realm", "push_certificate",
                  "scep_config", "scep_verification",
                  "blueprint")


class UserEnrollmentForm(forms.ModelForm):
    class Meta:
        model = UserEnrollment
        fields = ("name", "realm", "push_certificate",
                  "scep_config", "scep_verification",
                  "blueprint")


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
            if self.instance.topic:
                if push_certificate_d["topic"] != self.instance.topic:
                    raise forms.ValidationError("The new certificate has a different topic")
            else:
                if PushCertificate.objects.filter(topic=push_certificate_d["topic"]):
                    raise forms.ValidationError("A difference certificate with the same topic already exists")
            cleaned_data["push_certificate_d"] = push_certificate_d
        return cleaned_data

    def save(self):
        push_certificate_d = self.cleaned_data.pop("push_certificate_d")
        self.instance.name = self.cleaned_data["name"]
        for k, v in push_certificate_d.items():
            if k == "private_key":
                self.instance.set_private_key(v)
            else:
                setattr(self.instance, k, v)
        self.instance.save()
        return self.instance


class EnrolledDeviceSearchForm(forms.Form):
    q = forms.CharField(required=False,
                        widget=forms.TextInput(attrs={"placeholder": "Serial number, UDID",
                                                      "autofocus": True}))
    platform = forms.ChoiceField(
        choices=[("", "Platform"),] + [(p.value, p.value) for p in Platform], required=False)
    blueprint = forms.ModelChoiceField(queryset=Blueprint.objects.all(), required=False, empty_label="Blueprint")

    def get_queryset(self):
        qs = EnrolledDevice.objects.all().order_by("-updated_at")
        q = self.cleaned_data.get("q")
        if q:
            qs = qs.filter(Q(serial_number__icontains=q) | Q(udid__icontains=q))
        platform = self.cleaned_data.get("platform")
        if platform:
            qs = qs.filter(platform=platform)
        blueprint = self.cleaned_data.get("blueprint")
        if blueprint:
            qs = qs.filter(blueprint=blueprint)
        return qs

    def get_redirect_to(self):
        if self.has_changed():
            qs = self.get_queryset()
            if qs.count() == 1:
                return qs.first()


class ArtifactSearchForm(forms.Form):
    q = forms.CharField(required=False,
                        widget=forms.TextInput(attrs={"placeholder": "Name, Profile ID, Bundle ID",
                                                      "size": 24,
                                                      "autofocus": True}))
    artifact_type = forms.ChoiceField(
        choices=[("", "Type"),] + Artifact.Type.choices, required=False)
    channel = forms.ChoiceField(
        choices=[("", "Channel"),] + Channel.choices, required=False)
    platform = forms.ChoiceField(
        choices=[("", "Platform"),] + [(p.value, p.value) for p in Platform], required=False)
    blueprint = forms.ModelChoiceField(queryset=Blueprint.objects.all(), required=False, empty_label="Blueprint")

    def get_queryset(self):
        qs = Artifact.objects.annotate(Count("blueprintartifact", distinct=True)).order_by("name")
        q = self.cleaned_data.get("q")
        if q:
            qs = qs.filter(
                Q(name__icontains=q)
                | Q(artifactversion__enterprise_app__product_id__icontains=q)
                | Q(artifactversion__profile__payload_identifier__icontains=q)
                | Q(artifactversion__store_app__location_asset__asset__bundle_id__icontains=q)
            )
        artifact_type = self.cleaned_data.get("artifact_type")
        if artifact_type:
            qs = qs.filter(type=artifact_type)
        channel = self.cleaned_data.get("channel")
        if channel:
            qs = qs.filter(channel=channel)
        platform = self.cleaned_data.get("platform")
        if platform:
            qs = qs.filter(platforms__contains=[platform])
        blueprint = self.cleaned_data.get("blueprint")
        if blueprint:
            qs = qs.filter(blueprintartifact__blueprint=blueprint)
        return qs

    def get_redirect_to(self):
        if self.has_changed():
            qs = self.get_queryset()
            if qs.count() == 1:
                return qs.first()


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

    def save(self):
        # token
        dep_token = super().save()
        for k, v in self.cleaned_data["decrypted_dep_token"].items():
            if k == "access_secret":
                dep_token.set_access_secret(v)
            elif k == "consumer_secret":
                dep_token.set_consumer_secret(v)
            else:
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
            "push_certificate", "scep_config", "scep_verification",
            "blueprint",
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


class AppConfigurationMixin(forms.Form):
    configuration = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={"rows": 10}),
        help_text="The property list representation of the managed app configuration."
    )

    def set_initial_config(self):
        configuration = self.instance.get_configuration()
        if configuration:
            self.fields["configuration"].initial = plistlib.dumps(configuration).decode("utf-8")

    def clean_configuration(self):
        configuration = self.cleaned_data.pop("configuration")
        if configuration:
            if configuration.startswith("<dict>"):
                # to make it easier for the users
                configuration = f'<plist version="1.0">{configuration}</plist>'
            try:
                loaded_configuration = plistlib.loads(configuration.encode("utf-8"))
            except Exception:
                raise forms.ValidationError("Invalid property list")
            if not isinstance(loaded_configuration, dict):
                raise forms.ValidationError("Not a dictionary")
            configuration = plistlib.dumps(loaded_configuration)
        else:
            configuration = None
        return configuration


class BaseEnterpriseAppForm(forms.ModelForm, AppConfigurationMixin):
    package = forms.FileField(required=True,
                              help_text="macOS distribution package (.pkg) "
                                        "or iOS/iPadOS/tvOS application archive (.ipa)")

    class Meta:
        model = EnterpriseApp
        fields = [
            "package",
            "ios_app",
            "install_as_managed",
            "remove_on_unenroll",
        ]

    def clean(self):
        super().clean()
        # package
        package = self.cleaned_data.get("package")
        if not package:
            return
        try:
            title, product_id, product_version, manifest, bundles, platforms = build_enterprise_app_manifest(package)
        except Exception as e:
            raise forms.ValidationError(f"Invalid app: {e}")
        self.instance.filename = package.name
        self.instance.bundles = bundles
        self.cleaned_data["name"] = title or product_id
        self.cleaned_data["product_id"] = product_id
        self.cleaned_data["product_version"] = product_version
        self.cleaned_data["manifest"] = manifest
        self.cleaned_data["platforms"] = platforms
        # management
        install_as_managed = self.cleaned_data.get("install_as_managed")
        remove_on_unenroll = self.cleaned_data.get("remove_on_unenroll")
        if not install_as_managed and remove_on_unenroll:
            self.add_error("remove_on_unenroll", "Only available if installed as managed is also set")


class UploadEnterpriseAppForm(BaseEnterpriseAppForm):
    def save(self):
        cleaned_data = self.cleaned_data
        name = cleaned_data.pop("name")
        platforms = cleaned_data.pop("platforms")
        platform_kwargs = {platform.value.lower(): True for platform in platforms}
        for i in range(100):
            try:
                with transaction.atomic():
                    artifact = Artifact.objects.create(name=name,
                                                       type=Artifact.Type.ENTERPRISE_APP,
                                                       channel=Channel.DEVICE,
                                                       platforms=platforms)
            except IntegrityError:
                name = f"{name} ({i + 1})"
            else:
                break
        else:
            raise RuntimeError("Could not find unique name for artifact")
        artifact_version = ArtifactVersion.objects.create(
            artifact=artifact,
            version=1,
            **platform_kwargs,
        )
        EnterpriseApp.objects.create(artifact_version=artifact_version, **cleaned_data)
        return artifact


class UpgradeEnterpriseAppForm(BaseEnterpriseAppForm):
    def __init__(self, *args, **kwargs):
        self.artifact = kwargs.pop("artifact")
        # hack to clear the field.
        # we do not want to show the package associated to the latest version (= instance)
        kwargs["instance"].package = None
        super().__init__(*args, **kwargs)

    def clean(self):
        super().clean()
        if "product_id" not in self.cleaned_data:
            return
        if self.instance.product_id != self.cleaned_data["product_id"]:
            self.add_error(
                "package",
                "The product ID of the new app is not identical to the product ID of the latest version"
            )
        has_changed = False
        for k in ("product_version",
                  "manifest",
                  "ios_app",
                  "configuration",
                  "install_as_managed",
                  "remove_on_unenroll"):
            old_val = getattr(self.instance, k)
            if hasattr(old_val, "tobytes"):  # memory view
                old_val = old_val.tobytes()
            new_val = self.cleaned_data.get(k)
            if old_val != new_val:
                has_changed = True
                break
        if not has_changed:
            self.add_error(None, "This version of the enterprise app is identical to the latest version")

    def save(self, artifact_version):
        self.instance.id = None  # force insert
        self.instance.artifact_version = artifact_version
        self.instance.product_id = self.cleaned_data["product_id"]
        self.instance.product_version = self.cleaned_data["product_version"]
        self.instance.manifest = self.cleaned_data["manifest"]
        self.instance.configuration = self.cleaned_data["configuration"]
        return super().save()


class BaseProfileForm(forms.ModelForm):
    source_file = forms.FileField(required=True,
                                  help_text="configuration profile file (.mobileconfig)")

    class Meta:
        model = Profile
        fields = []

    def clean(self):
        source_file = self.cleaned_data.get("source_file")
        if not source_file:
            return
        # read payload
        data = source_file.read()
        try:
            _, data = verify_signed_payload(data)
        except Exception:
            # probably not a signed payload
            pass
        try:
            payload = plistlib.loads(data)
        except Exception:
            self.add_error("source_file", "This file is not a plist.")
            return
        # payload identifier
        try:
            self.instance.payload_identifier = payload["PayloadIdentifier"]
        except KeyError:
            self.add_error("source_file", "Missing PayloadIdentifier.")
            return
        # payload uuid
        try:
            self.instance.payload_uuid = payload["PayloadUUID"]
        except KeyError:
            self.add_error("source_file", "Missing PayloadUUID.")
            return
        # channel
        payload_scope = payload.get("PayloadScope", "User")
        if payload_scope == "System":
            channel = Channel.DEVICE
        elif payload_scope == "User":
            channel = Channel.USER
        else:
            self.add_error("source_file", f"Unknown PayloadScope: {payload_scope}.")
            return
        self.cleaned_data["channel"] = channel
        # other keys
        for payload_key, obj_key in (("PayloadDisplayName", "payload_display_name"),
                                     ("PayloadDescription", "payload_description")):
            setattr(self.instance, obj_key, payload.get(payload_key) or "")
        # source
        self.cleaned_data["source"] = data
        # filename
        source_file = self.cleaned_data.pop("source_file")
        self.instance.filename = source_file.name


class UploadProfileForm(BaseProfileForm):
    def save(self):
        cleaned_data = self.cleaned_data
        name = self.instance.payload_display_name or self.instance.payload_identifier
        channel = cleaned_data.pop("channel")
        for i in range(100):
            try:
                with transaction.atomic():
                    artifact = Artifact.objects.create(name=name,
                                                       type=Artifact.Type.PROFILE,
                                                       channel=channel,
                                                       platforms=Platform.values)
            except IntegrityError:
                name = f"{name} ({i + 1})"
            else:
                break
        else:
            raise RuntimeError("Could not find unique name for artifact")
        self.instance.artifact_version = ArtifactVersion.objects.create(
            artifact=artifact,
            version=1,
            **{platform.lower(): True for platform in Platform.values}
        )
        self.instance.source = self.cleaned_data["source"]
        super().save()
        return artifact


class UpgradeProfileForm(BaseProfileForm):
    def __init__(self, *args, **kwargs):
        self.artifact = kwargs.pop("artifact")
        super().__init__(*args, **kwargs)

    def clean(self):
        super().clean()
        if self.cleaned_data:
            # check channel
            if self.cleaned_data.get("channel") != self.artifact.get_channel():
                self.add_error("source_file",
                               "The channel of the profile must match the channel of the artifact.")
            if self.instance.source.tobytes() == self.cleaned_data["source"]:
                self.add_error("source_file",
                               "This profile is not different from the latest one.")

    def save(self, artifact_version):
        self.instance.id = None  # force insert
        self.instance.source = self.cleaned_data["source"]
        self.instance.artifact_version = artifact_version
        return super().save()


class PlatformsWidget(forms.CheckboxSelectMultiple):
    def __init__(self, attrs=None, choices=()):
        super().__init__(attrs, choices=Platform.choices)

    def format_value(self, value):
        if isinstance(value, str) and value:
            value = [v.strip() for v in value.split(",")]
        return super().format_value(value)


class UpdateArtifactForm(forms.ModelForm):
    class Meta:
        model = Artifact
        exclude = ["type", "channel"]
        widgets = {"platforms": PlatformsWidget}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.type in (Artifact.Type.STORE_APP,):
            del self.fields["platforms"]
        self.fields["requires"].queryset = self.fields["requires"].queryset.exclude(pk=self.instance.pk)

    def save(self):
        instance = super().save()
        for blueprint in instance.blueprints():
            update_blueprint_serialized_artifacts(blueprint)
        return instance


class BlueprintItemFormMixin:
    def __init__(self, *args, **kwargs):
        self.artifact = kwargs.pop("artifact")
        super().__init__(*args, **kwargs)
        # add a class to the os version checkboxes
        for visible in self.visible_fields():
            field = visible.field
            if isinstance(field, forms.BooleanField):
                field.widget.attrs["class"] = "os-version-cb"
        # tag qs
        tag_qs = Tag.objects.select_related("meta_business_unit", "taxonomy").all()
        self.fields['excluded_tags'].queryset = tag_qs
        # tag shards
        self.tag_shards = []
        existing_tag_shard_dict = {}
        if self.instance.pk:
            existing_tag_shard_dict = self.instance.tag_shards
        for tag in tag_qs:
            self.tag_shards.append(
                (tag, tag in existing_tag_shard_dict, existing_tag_shard_dict.get(tag, self.instance.shard_modulo))
            )
        self.tag_shards.sort(key=lambda t: t[0].name.lower())

    def clean(self):
        super().clean()
        # platforms & min max versions
        platform_active = False
        for platform in Platform.values:
            field = platform.lower()
            if not self.cleaned_data.get(field, False):
                self.cleaned_data[f"{field}_min_version"] = ""
                self.cleaned_data[f"{field}_max_version"] = ""
            else:
                platform_active = True
                if platform not in self.artifact.platforms:
                    self.add_error(field, "Platform not available for this artifact")
        if not platform_active:
            self.add_error(None, "You need to activate at least one platform")
        # shards
        default_shard = self.cleaned_data.get("default_shard")
        shard_modulo = self.cleaned_data.get("shard_modulo")
        if default_shard and shard_modulo and shard_modulo < default_shard:
            self.add_error("default_shard", "Must be less than or equal to the shard modulo")
        # excluded tags
        for tag in self.cleaned_data.get("excluded_tags", []):
            if f"tag-shard-{tag.pk}" in self.data:
                self.add_error("excluded_tags", f"Conflict with {tag} shard")
        # tag shards
        for tag, _, _ in self.tag_shards:
            try:
                shard = int(self.data[f"tag-shard-{tag.pk}"])
            except Exception:
                continue
            if isinstance(shard_modulo, int):
                shard = min(shard, shard_modulo)
            self.cleaned_data.setdefault("tag_shards", {})[tag] = shard


class BlueprintArtifactForm(BlueprintItemFormMixin, forms.ModelForm):
    class Meta:
        model = BlueprintArtifact
        fields = ("blueprint",
                  "ios", "ios_min_version", "ios_max_version",
                  "ipados", "ipados_min_version", "ipados_max_version",
                  "macos", "macos_min_version", "macos_max_version",
                  "tvos", "tvos_min_version", "tvos_max_version",
                  "shard_modulo", "default_shard",
                  "excluded_tags")
        labels = {
            "ios": "iOS",
            "ios_min_version": "min version (incl.)",
            "ios_max_version": "max version (excl.)",
            "ipados": "iPadOS",
            "ipados_min_version": "min version (incl.)",
            "ipados_max_version": "max version (excl.)",
            "macos": "macOS",
            "macos_min_version": "min version (incl.)",
            "macos_max_version": "max version (excl.)",
            "tvos": "tvOS",
            "tvos_min_version": "min version (incl.)",
            "tvos_max_version": "max version (excl.)",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # blueprint qs
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
        instance = super().save(*args, **kwargs)
        # tag shards
        tag_shards = self.cleaned_data.get("tag_shards", {})
        instance.item_tags.exclude(tag__in=tag_shards.keys()).delete()
        for tag, shard in tag_shards.items():
            BlueprintArtifactTag.objects.update_or_create(
                blueprint_artifact=instance,
                tag=tag,
                defaults={"shard": shard}
            )
        # update blueprint
        update_blueprint_serialized_artifacts(instance.blueprint)
        return instance


class ArtifactVersionForm(BlueprintItemFormMixin, forms.ModelForm):
    class Meta:
        model = ArtifactVersion
        fields = ("ios", "ios_min_version", "ios_max_version",
                  "ipados", "ipados_min_version", "ipados_max_version",
                  "macos", "macos_min_version", "macos_max_version",
                  "tvos", "tvos_min_version", "tvos_max_version",
                  "shard_modulo", "default_shard",
                  "excluded_tags")
        labels = {
            "ios": "iOS",
            "ios_min_version": "min version (incl.)",
            "ios_max_version": "max version (excl.)",
            "ipados": "iPadOS",
            "ipados_min_version": "min version (incl.)",
            "ipados_max_version": "max version (excl.)",
            "macos": "macOS",
            "macos_min_version": "min version (incl.)",
            "macos_max_version": "max version (excl.)",
            "tvos": "tvOS",
            "tvos_min_version": "min version (incl.)",
            "tvos_max_version": "max version (excl.)",
        }

    def save(self, *args, **kwargs):
        self.instance.artifact = self.artifact
        if kwargs.pop("force_insert", False):
            self.instance.id = None  # force an insert
            self.instance.version = self.instance.version + 1
        instance = super().save()
        # tag shards
        tag_shards = self.cleaned_data.get("tag_shards", {})
        instance.item_tags.exclude(tag__in=tag_shards.keys()).delete()
        for tag, shard in tag_shards.items():
            ArtifactVersionTag.objects.update_or_create(
                artifact_version=instance,
                tag=tag,
                defaults={"shard": shard}
            )
        # update blueprints
        for blueprint in self.artifact.blueprints():
            update_blueprint_serialized_artifacts(blueprint)
        return instance


class SCEPConfigForm(forms.ModelForm):
    class Meta:
        model = SCEPConfig
        fields = "__all__"


class LocationForm(forms.ModelForm):
    server_token_file = forms.FileField(
        required=True,
        help_text="Server token (*.vpptoken), downloaded from the Apple business manager."
    )

    class Meta:
        model = Location
        fields = []

    def clean(self):
        server_token_file = self.cleaned_data["server_token_file"]
        if not server_token_file:
            return
        raw_server_token = server_token_file.read()
        server_token = raw_server_token.decode("utf-8")
        # base64 + json test
        try:
            server_token_json = json.loads(base64.b64decode(raw_server_token))
        except ValueError:
            self.add_error("server_token_file", "Not a valid server token")
            return
        # token hash
        server_token_hash = hashlib.sha1(raw_server_token).hexdigest()
        test_qs = Location.objects.filter(server_token_hash=server_token_hash)
        if self.instance.pk:
            test_qs = test_qs.exclude(pk=self.instance.pk)
        if test_qs.count():
            self.add_error("server_token_file", "A location with the same server token already exists.")
            return
        self.cleaned_data["server_token_hash"] = server_token_hash
        try:
            self.cleaned_data["organization_name"] = server_token_json["orgName"]
        except Exception:
            self.add_error("server_token_file", "Could not get organization name.")
            return
        ab_client = AppsBooksClient(server_token)
        try:
            config = ab_client.get_client_config()
        except Exception:
            msg = "Could not get client information"
            logger.exception(msg)
            self.add_error("server_token_file", msg)
            return
        for config_attr, model_attr in (("countryISO2ACode", "country_code"),
                                        ("uId", "library_uid"),
                                        ("locationName", "name"),
                                        ("defaultPlatform", "platform"),
                                        ("websiteURL", "website_url")):
            val = config.get(config_attr)
            if not isinstance(val, str):
                self.add_error("server_token_file", f"Missing or bad {config_attr}.")
            else:
                self.cleaned_data[model_attr] = val
        try:
            self.cleaned_data["server_token_expiration_date"] = parser.parse(config["tokenExpirationDate"])
        except KeyError:
            self.add_error("server_token_file", "Missing tokenExpirationDate.")
            return
        except Exception:
            msg = "Could not parse server token expiration date."
            logger.exception(msg)
            self.add_error("server_token_file", msg)
            return
        self.cleaned_data["server_token"] = server_token
        return self.cleaned_data

    def save(self):
        location = super().save(commit=False)
        for attr in ("server_token_hash",
                     "server_token_expiration_date",
                     "organization_name",
                     "country_code",
                     "library_uid",
                     "name",
                     "platform",
                     "website_url"):
            setattr(location, attr, self.cleaned_data[attr])
        notification_auth_token = location.set_notification_auth_token()
        location.save()
        location.set_server_token(self.cleaned_data["server_token"])
        location.save()

        def update_client_config():
            ab_client = AppsBooksClient.from_location(location)
            ab_client.update_client_config(notification_auth_token)
            # TODO: retry

        transaction.on_commit(update_client_config)
        return location


class StoreAppForm(forms.ModelForm, AppConfigurationMixin):
    field_order = [
        "associated_domains",
        "associated_domains_enable_direct_downloads",
        "configuration",
        "prevent_backup",
        "removable",
        "remove_on_unenroll",
        "vpn_uuid",
        "content_filter_uuid",
        "dns_proxy_uuid"
    ]

    class Meta:
        model = StoreApp
        fields = [
            "associated_domains",
            "associated_domains_enable_direct_downloads",
            "content_filter_uuid",
            "dns_proxy_uuid",
            "prevent_backup",
            "removable",
            "remove_on_unenroll",
            "vpn_uuid",
        ]
        widgets = {
            "content_filter_uuid": forms.TextInput,
            "dns_proxy_uuid": forms.TextInput,
            "vpn_uuid": forms.TextInput,
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.set_initial_config()

    def save(self, *args, **kwargs):
        self.instance.configuration = self.cleaned_data["configuration"]
        return super().save(*args, **kwargs)

    def clean_content_filter_uuid(self):
        content_filter_uuid = self.cleaned_data.get("content_filter_uuid")
        if not content_filter_uuid:
            return None

    def clean_dns_proxy_uuid(self):
        dns_proxy_uuid = self.cleaned_data.get("dns_proxy_uuid")
        if not dns_proxy_uuid:
            return None

    def clean_vpn_uuid(self):
        vpn_uuid = self.cleaned_data.get("vpn_uuid")
        if not vpn_uuid:
            return None


class LocationAssetChoiceField(forms.ModelChoiceField):
    def label_from_instance(self, obj):
        return str(obj.location)


class CreateAssetArtifactForm(StoreAppForm):
    location_asset = LocationAssetChoiceField(label="Location", queryset=LocationAsset.objects.none(), required=True)
    name = forms.CharField(required=True)
    field_order = ["name", "location_asset"] + StoreAppForm.field_order

    class Meta(StoreAppForm.Meta):
        fields = ["name", "location_asset"] + StoreAppForm.Meta.fields

    def clean_name(self):
        name = self.cleaned_data.get("name")
        if Artifact.objects.filter(name=name).count():
            raise forms.ValidationError("An artifact with this name already exists")
        return name

    def __init__(self, *args, **kwargs):
        self.asset = kwargs.pop("asset")
        super().__init__(*args, **kwargs)
        # location qs
        self.fields["location_asset"].queryset = self.asset.locationasset_set.all()
        # default name
        name = self.asset.name
        for i in range(1, 11):
            if Artifact.objects.filter(name=name).count() == 0:
                break
            name = f"{self.asset.name} ({i})"
        else:
            logger.error("Could not find unique name for asset %s", self.asset.pk)
            name = self.asset.name
        self.fields["name"].initial = name

    def save(self):
        artifact = Artifact.objects.create(
            name=self.cleaned_data["name"],
            type=Artifact.Type.STORE_APP,
            channel=Channel.DEVICE,
            platforms=self.asset.supported_platforms,
        )
        artifact_version = ArtifactVersion.objects.create(
            artifact=artifact,
            version=1,
            **{platform.lower(): True for platform in self.asset.supported_platforms},
        )
        store_app = super().save(commit=False)
        store_app.artifact_version = artifact_version
        store_app.save()
        return store_app


class UpgradeStoreAppForm(StoreAppForm):
    def __init__(self, *args, **kwargs):
        self.artifact = kwargs.pop("artifact")
        super().__init__(*args, **kwargs)

    def clean(self):
        super().clean()
        has_changed = False
        for field_name in ["configuration"] + self.Meta.fields:
            old_val = getattr(self.instance, field_name)
            if hasattr(old_val, "tobytes"):  # memory view
                old_val = old_val.tobytes()
            new_val = self.cleaned_data.get(field_name)
            if new_val != old_val:
                has_changed = True
                break
        if not has_changed:
            self.add_error(None, "This version of the store app is identical to the latest version")

    def save(self, artifact_version):
        self.instance.id = None  # force insert
        self.instance.artifact_version = artifact_version
        return super().save()

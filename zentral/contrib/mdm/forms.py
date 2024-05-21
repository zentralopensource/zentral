import base64
import hashlib
import json
import logging
from dateutil import parser
from django import forms
from django.db import IntegrityError, transaction
from django.db.models import Count, Q
from realms.utils import build_password_hash_dict
from zentral.contrib.inventory.models import Tag
from zentral.utils.os_version import make_comparable_os_version
from .app_manifest import read_package_info, validate_configuration
from .apps_books import AppsBooksClient
from .artifacts import update_blueprint_serialized_artifacts
from .commands.set_recovery_lock import validate_recovery_password
from .crypto import generate_push_certificate_key_bytes, load_push_certificate_and_key
from .dep import decrypt_dep_token
from .dep_client import DEPClient
from .payloads import get_configuration_profile_info
from .models import (Artifact, ArtifactVersion, ArtifactVersionTag,
                     Blueprint, BlueprintArtifact, BlueprintArtifactTag, Channel,
                     DEPDevice, DEPOrganization, DEPEnrollment, DEPToken, DEPVirtualServer,
                     EnrolledDevice, EnterpriseApp, Platform,
                     FileVaultConfig, RecoveryPasswordConfig, SCEPConfig,
                     OTAEnrollment, UserEnrollment, PushCertificate,
                     Profile, Location, LocationAsset, StoreApp,
                     SoftwareUpdateEnforcement)
from .skip_keys import skippable_setup_panes


logger = logging.getLogger("zentral.contrib.mdm.forms")


class OTAEnrollmentForm(forms.ModelForm):
    class Meta:
        model = OTAEnrollment
        fields = ("name", "display_name", "realm", "push_certificate",
                  "scep_config", "scep_verification",
                  "blueprint")


class UserEnrollmentForm(forms.ModelForm):
    class Meta:
        model = UserEnrollment
        fields = ("name", "display_name", "realm", "push_certificate",
                  "scep_config", "scep_verification",
                  "blueprint")

    def clean(self):
        cleaned_data = super().clean()
        if not cleaned_data.get("realm"):
            self.add_error("realm", "This field is required")
        return cleaned_data


class CreatePushCertificateForm(forms.ModelForm):
    view_title = "Create"
    view_action = "Create MDM push certificate"

    class Meta:
        model = PushCertificate
        fields = ("name",)

    def save(self, *args, **kwargs):
        push_certificate = super().save(commit=False)
        push_certificate.set_private_key(generate_push_certificate_key_bytes())
        push_certificate.save()
        return push_certificate


class BasePushCertificateForm(forms.ModelForm):
    certificate_file = forms.FileField(required=True)

    class Meta:
        model = PushCertificate
        fields = ("name",)

    def get_key_bytes():
        raise NotImplementedError

    def clean(self):
        cleaned_data = super().clean()
        certificate_file = cleaned_data.pop("certificate_file", None)
        key_bytes, key_password = self.get_key_bytes()
        if certificate_file and key_bytes:
            try:
                push_certificate_d = load_push_certificate_and_key(
                    certificate_file.read(),
                    key_bytes, key_password
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


class PushCertificateForm(BasePushCertificateForm):
    key_file = forms.FileField(required=True)
    key_password = forms.CharField(widget=forms.PasswordInput, required=False)

    def get_key_bytes(self):
        key_file = self.cleaned_data.pop("key_file", None)
        key_password = self.cleaned_data.pop("key_password", None)
        return key_file.read(), key_password

    @property
    def view_title(self):
        if self.instance.pk:
            return "Renew"
        else:
            return "Upload"

    @property
    def view_action(self):
        if self.instance.pk:
            return "Renew MDM push certificate and key"
        else:
            return "Upload MDM push certificate and key"


class PushCertificateCertificateForm(BasePushCertificateForm):
    view_title = "Upload"
    view_action = "Upload MDM push certificate"

    def get_key_bytes(self):
        return self.instance.get_private_key(), None

    def save(self):
        push_certificate = super().save()
        if push_certificate.signed_csr:
            push_certificate.signed_csr = None
            push_certificate.signed_csr_updated_at = None
            push_certificate.save()
        return push_certificate


class DEPDeviceSearchForm(forms.Form):
    template_name = "django/forms/search.html"

    q = forms.CharField(required=False,
                        widget=forms.TextInput(attrs={"placeholder": "Serial number",
                                                      "autofocus": True}))
    enrollment = forms.ModelChoiceField(queryset=DEPEnrollment.objects.all(), required=False, empty_label="Enrollment")
    server = forms.ModelChoiceField(queryset=DEPVirtualServer.objects.all(), required=False, empty_label="Server")
    include_deleted = forms.BooleanField(label="Incl. deleted?", required=False)

    def get_queryset(self):
        qs = DEPDevice.objects.all().order_by("-updated_at")
        q = self.cleaned_data.get("q")
        if q:
            qs = qs.filter(Q(serial_number__icontains=q))
        include_deleted = self.cleaned_data.get("include_deleted")
        if not include_deleted:
            qs = qs.exclude(last_op_type=DEPDevice.OP_TYPE_DELETED)
        enrollment = self.cleaned_data.get("enrollment")
        if enrollment:
            qs = qs.filter(enrollment=enrollment)
        server = self.cleaned_data.get("server")
        if server:
            qs = qs.filter(virtual_server=server)
        qs = qs.order_by("-updated_at")
        return qs

    def get_redirect_to(self):
        if self.has_changed():
            qs = self.get_queryset()
            if qs.count() == 1:
                return qs.first()


class EnrolledDeviceSearchForm(forms.Form):
    template_name = "django/forms/search.html"

    q = forms.CharField(required=False,
                        widget=forms.TextInput(attrs={"placeholder": "Serial number, UDID",
                                                      "autofocus": True}))
    platform = forms.ChoiceField(
        choices=[("", "..."), ] + [(p.value, p.value) for p in Platform], required=False)
    blueprint = forms.ModelChoiceField(queryset=Blueprint.objects.all(), required=False, empty_label="...")

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
    template_name = "django/forms/search.html"

    q = forms.CharField(required=False,
                        widget=forms.TextInput(attrs={"placeholder": "Name, Profile ID, Bundle ID",
                                                      "size": 24,
                                                      "autofocus": True}))
    artifact_type = forms.ChoiceField(
        choices=[("", "..."), ] + Artifact.Type.choices, required=False)
    channel = forms.ChoiceField(
        choices=[("", "..."), ] + Channel.choices, required=False)
    platform = forms.ChoiceField(
        choices=[("", "..."), ] + [(p.value, p.value) for p in Platform], required=False)
    blueprint = forms.ModelChoiceField(queryset=Blueprint.objects.all(), required=False, empty_label="...")

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


class UpdateDEPVirtualServerForm(forms.ModelForm):
    class Meta:
        model = DEPVirtualServer
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["default_enrollment"].queryset = self.fields["default_enrollment"].queryset.filter(
            virtual_server=self.instance
        )


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
        for key, content in skippable_setup_panes:
            if self.instance.pk:
                initial = key in self.instance.skip_setup_items
            else:
                initial = False
            self.fields[f"ssp-{key}"] = forms.BooleanField(
                label=content,
                initial=initial,
                required=False
            )
            field_order.append(key)
        field_order.extend(["display_name", "realm", "use_realm_user", "username_pattern", "realm_user_is_admin",
                            "admin_full_name", "admin_short_name", "admin_password",
                            "ios_max_version", "ios_min_version", "macos_max_version", "macos_min_version"])
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

    def clean_username_pattern(self):
        use_realm_user = self.cleaned_data.get("use_realm_user")
        username_pattern = self.cleaned_data.get("username_pattern")
        if not use_realm_user:
            if username_pattern:
                raise forms.ValidationError("This field can only be used if the 'use realm user' option is ticked")
        else:
            if not username_pattern:
                raise forms.ValidationError("This field is required when the 'use realm user' option is ticked")
        return username_pattern

    def clean_realm_user_is_admin(self):
        use_realm_user = self.cleaned_data.get("use_realm_user")
        realm_user_is_admin = self.cleaned_data.get("realm_user_is_admin")
        if realm_user_is_admin and not use_realm_user:
            raise forms.ValidationError("This option is only valid if the 'use realm user' option is ticked too")
        return realm_user_is_admin

    def _clean_os_version(self, platform, limit):
        fieldname = f"{platform}_{limit}_version"
        min_version = self.cleaned_data.get(fieldname)
        if min_version and make_comparable_os_version(min_version) == (0, 0, 0):
            raise forms.ValidationError("Not a valid OS version")
        return min_version

    def clean_ios_max_version(self):
        return self._clean_os_version("ios", "max")

    def clean_ios_min_version(self):
        return self._clean_os_version("ios", "min")

    def clean_macos_max_version(self):
        return self._clean_os_version("macos", "max")

    def clean_macos_min_version(self):
        return self._clean_os_version("macos", "min")

    def clean_admin_password(self):
        password = self.cleaned_data.get("admin_password")
        if password:
            self.cleaned_data["admin_password_hash"] = build_password_hash_dict(password)

    def admin_info_incomplete(self):
        return len([attr for attr in (
                        self.cleaned_data.get(i)
                        for i in ("admin_full_name", "admin_short_name", "admin_password_hash")
                    ) if attr]) in (1, 2)

    def has_admin_info(self):
        return self.cleaned_data.get("admin_full_name") and not self.admin_info_incomplete()

    def update_password(self):
        return not self.admin_info_incomplete()

    def reset_password(self):
        return False

    def clean(self):
        super().clean()
        skip_setup_items = []
        for key, _ in skippable_setup_panes:
            if self.cleaned_data.get(f"ssp-{key}", False):
                skip_setup_items.append(key)
        if self.admin_info_incomplete():
            raise forms.ValidationError("Admin information incomplete")
        if self.has_admin_info() and not self.cleaned_data.get("await_device_configured"):
            self.add_error("await_device_configured", "Required for the admin account setup")
        self.cleaned_data['skip_setup_items'] = skip_setup_items

    def save(self, *args, **kwargs):
        commit = kwargs.pop("commit", True)
        kwargs["commit"] = False
        dep_profile = super().save(**kwargs)
        dep_profile.skip_setup_items = self.cleaned_data["skip_setup_items"]
        if self.update_password():
            dep_profile.admin_password_hash = self.cleaned_data.get("admin_password_hash")
        elif self.reset_password():
            dep_profile.admin_password_hash = None
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

    def admin_info_incomplete(self):
        attr_count = len(
            [attr for attr in (
                 self.cleaned_data.get(i)
                 for i in ("admin_full_name", "admin_short_name", "admin_password_hash")
             ) if attr]
        )
        return (attr_count == 1 or
                (attr_count == 2 and (
                    # full or short name missing
                    self.cleaned_data.get("admin_password_hash")
                    # password missing and not already present in the object
                    or not self.instance.admin_password_hash
                )))

    def update_password(self):
        return (
            self.cleaned_data.get("admin_full_name")
            and self.cleaned_data.get("admin_short_name")
            and self.cleaned_data.get("admin_password_hash")
        )

    def reset_password(self):
        return (
            not self.cleaned_data.get("admin_full_name")
            and not self.cleaned_data.get("admin_short_name")
            and not self.cleaned_data.get("admin_password_hash")
        )


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
        configuration_plist = self.instance.get_configuration_plist()
        if configuration_plist:
            self.fields["configuration"].initial = configuration_plist

    def clean_configuration(self):
        configuration = self.cleaned_data.pop("configuration")
        try:
            return validate_configuration(configuration)
        except ValueError as e:
            raise forms.ValidationError(str(e))


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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['ios_app'].label = "iOS app"

    def clean(self):
        super().clean()
        # package
        package = self.cleaned_data.get("package")
        if not package:
            return
        try:
            name, platforms, ea_data = read_package_info(package, compute_sha256=True)
        except Exception as e:
            raise forms.ValidationError(f"Invalid app: {e}")
        self.cleaned_data["name"] = name
        self.cleaned_data["filename"] = package.name
        self.cleaned_data["platforms"] = platforms
        self.cleaned_data.update(ea_data)
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
        for k in ("manifest",
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
        # save non-field attributes (configuration is not editable, so not a standard "field")
        for attr in ("package_sha256",
                     "package_size",
                     "configuration",
                     "filename",
                     "product_id",
                     "product_version",
                     "bundles",
                     "manifest"):
            setattr(self.instance, attr, self.cleaned_data[attr])
        return super().save()


class BaseProfileForm(forms.ModelForm):
    source_file = forms.FileField(required=True,
                                  help_text="configuration profile file (.mobileconfig)")

    class Meta:
        model = Profile
        fields = []

    def clean(self):
        source_file = self.cleaned_data.pop("source_file")
        if not source_file:
            return
        # read payload
        data = source_file.read()
        try:
            data, info = get_configuration_profile_info(data)
        except ValueError as e:
            self.add_error("source_file", str(e))
        else:
            self.cleaned_data["source"] = data
            self.instance.filename = source_file.name
            for attr, val in info.items():
                if attr != "channel":
                    setattr(self.instance, attr, val)
                else:
                    self.cleaned_data[attr] = val


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
            existing_tag_shard_dict = {ts["tag"]: ts["shard"] for ts in self.instance.tag_shards}
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


class FileVaultConfigForm(forms.ModelForm):
    class Meta:
        model = FileVaultConfig
        fields = "__all__"

    def clean(self):
        super().clean()
        at_login_only = self.cleaned_data.get("at_login_only")
        if not at_login_only:
            self.cleaned_data["bypass_attempts"] = -1
        else:
            bypass_attempts = self.cleaned_data.get("bypass_attempts")
            if isinstance(bypass_attempts, int) and bypass_attempts < 0:
                self.add_error("bypass_attempts", "Must be at least 0 when enablement deferred at login")


class RecoveryPasswordConfigForm(forms.ModelForm):
    static_password = forms.CharField(
        widget=forms.PasswordInput(render_value=True),
        validators=[validate_recovery_password],
        required=False, strip=True
    )
    field_order = [
        "name",
        "dynamic_password",
        "static_password",
        "rotation_interval_days",
        "rotate_firmware_password",
    ]

    class Meta:
        model = RecoveryPasswordConfig
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields["static_password"].initial = self.instance.get_static_password() or ""

    def clean(self):
        super().clean()
        dynamic_password = self.cleaned_data.get("dynamic_password")
        if not dynamic_password:
            static_password = self.cleaned_data.get("static_password")
            if not static_password and "static_password" not in self.errors:
                self.add_error("static_password", "This field is required when not using dynamic passwords.")
            self.cleaned_data["rotation_interval_days"] = 0
            self.cleaned_data["rotate_firmware_password"] = False
        else:
            if (
                self.cleaned_data.get("rotate_firmware_password")
                and not self.cleaned_data.get("rotation_interval_days")
            ):
                self.add_error("rotate_firmware_password",
                               "Cannot be set without a rotation interval.")

    def save(self):
        if self.instance.pk and not self.cleaned_data.get("dynamic_password"):
            self.instance.set_static_password(None)
        obj = super().save()
        if not obj.dynamic_password:
            obj.set_static_password(self.cleaned_data["static_password"])
            obj.save()
        return obj


class SoftwareUpdateEnforcementForm(forms.ModelForm):
    enforcement_type = forms.ChoiceField(
        label="Type",
        required=True,
        widget=forms.RadioSelect,
        choices=(("ONE_TIME", "One time"),
                 ("LATEST", "Latest")),
        initial="LATEST",
    )
    field_order = (
        "name",
        "details_url",
        "platforms",
        "tags",
        "enforcement_type",
        "os_version", "build_version", "local_datetime",
        "max_os_version", "delay_days", "local_time",
    )
    latest_fields = ("max_os_version", "delay_days", "local_time")
    one_time_fields = ("os_version", "build_version", "local_datetime")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for widget_class, fields in (("one-time-enforcement", self.one_time_fields),
                                     ("latest-enforcement", self.latest_fields),):
            for field in fields:
                self.fields[field].widget.attrs["class"] = widget_class
        if self.instance.pk:
            self.fields["enforcement_type"].initial = "ONE_TIME" if self.instance.os_version else "LATEST"

    class Meta:
        model = SoftwareUpdateEnforcement
        fields = "__all__"
        widgets = {"platforms": PlatformsWidget}

    def _clean_os_version(self, os_version):
        if os_version and make_comparable_os_version(os_version) == (0, 0, 0):
            raise forms.ValidationError("Not a valid OS version")
        return os_version

    def clean_max_os_version(self):
        return self._clean_os_version(self.cleaned_data.get("max_os_version"))

    def clean_os_version(self):
        return self._clean_os_version(self.cleaned_data.get("os_version"))

    def clean(self):
        super().clean()
        enforcement_type = self.cleaned_data.get("enforcement_type")
        if enforcement_type == "ONE_TIME":
            required_fields = (f for f in self.one_time_fields if f != "build_version")
            other_fields = self.latest_fields
        else:
            required_fields = self.latest_fields
            other_fields = self.one_time_fields
        for field in required_fields:
            value = self.cleaned_data.get(field)
            if not self.has_error(field) and (value is None or value == ""):
                self.add_error(field, "This field is required")
        for field in other_fields:
            setattr(self.instance, field, "" if field not in ("delay_days", "local_time", "local_datetime") else None)


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

import datetime
from functools import partial
import hashlib
import logging
import mimetypes
import os.path
import plistlib
import uuid
from django.contrib.postgres.fields import ArrayField, DateRangeField
from django.core.validators import MinLengthValidator, MinValueValidator, MaxValueValidator
from django.db import connection, models
from django.db.models import Count
from django.db.models.signals import post_delete
from django.dispatch import receiver
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.utils.functional import cached_property
from django.utils.text import slugify
from django.utils.timesince import timesince
from django.utils.translation import gettext_lazy as _
from realms.models import Realm, RealmGroup, RealmUser
from zentral.conf import settings
from zentral.contrib.inventory.models import EnrollmentSecret, EnrollmentSecretRequest, MetaMachine, Tag
from zentral.core.incidents.models import Severity
from zentral.core.secret_engines import decrypt, decrypt_str, encrypt, encrypt_str, rewrap
from zentral.utils.iso_3166_1 import ISO_3166_1_ALPHA_2_CHOICES
from zentral.utils.iso_639_1 import ISO_639_1_CHOICES
from zentral.utils.os_version import make_comparable_os_version
from zentral.utils.payloads import get_payload_identifier
from zentral.utils.storage import select_dist_storage
from zentral.utils.time import naive_truncated_isoformat
from .exceptions import EnrollmentSessionStatusError
from .scep import SCEPChallengeType, get_scep_challenge, load_scep_challenge


logger = logging.getLogger("zentral.contrib.mdm.models")


class Channel(models.TextChoices):
    DEVICE = "Device"
    USER = "User"


class Platform(models.TextChoices):
    IOS = ("iOS", "iOS")
    IPADOS = ("iPadOS", "iPadOS")
    MACOS = ("macOS", "macOS")
    TVOS = ("tvOS", "tvOS")


# used only for an ArrayField to avoid triggering the warning about shared default objects
def get_platform_values():
    return Platform.values


# Push certificates


class PushCertificateManager(models.Manager):
    def for_update(self):
        return self.filter(provisioning_uid__isnull=True)

    def for_deletion(self):
        return self.for_update().annotate(
            enrolled_device_count=Count("enrolleddevice"),
            dep_enrollment_count=Count("depenrollment"),
            ota_enrollment_count=Count("otaenrollment"),
            user_enrollment_count=Count("userenrollment"),
        ).filter(
            enrolled_device_count=0,
            dep_enrollment_count=0,
            ota_enrollment_count=0,
            user_enrollment_count=0,
        )


class PushCertificate(models.Model):
    provisioning_uid = models.CharField(max_length=256, unique=True, null=True, editable=False)
    name = models.CharField(max_length=256, unique=True)
    topic = models.CharField(max_length=256, null=True, unique=True, editable=False)
    not_before = models.DateTimeField(null=True, editable=False)
    not_after = models.DateTimeField(null=True, editable=False)
    certificate = models.BinaryField(null=True)
    private_key = models.TextField(default="", editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = PushCertificateManager()

    class Meta:
        ordering = ('name', 'topic')

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("mdm:push_certificate", args=(self.pk,))

    def can_be_deleted(self):
        return PushCertificate.objects.for_deletion().filter(pk=self.pk).exists()

    def can_be_updated(self):
        return PushCertificate.objects.for_update().filter(pk=self.pk).exists()

    # secret

    def _get_secret_engine_kwargs(self, field):
        if not self.pk:
            raise ValueError("PushCertificate must have a pk")
        return {"pk": self.pk, "model": "mdm.pushcertificate", "field": field}

    def get_private_key(self):
        return decrypt(self.private_key, **self._get_secret_engine_kwargs("private_key"))

    def set_private_key(self, private_key):
        self.private_key = encrypt(private_key, **self._get_secret_engine_kwargs("private_key"))

    def rewrap_secrets(self):
        self.private_key = rewrap(self.private_key, **self._get_secret_engine_kwargs("private_key"))


# FileVault


class FileVaultConfigManager(models.Manager):
    def can_be_deleted(self):
        return self.annotate(bp_count=Count("blueprint")).filter(bp_count=0)


class FileVaultConfig(models.Model):
    name = models.CharField(max_length=256, unique=True)
    escrow_location_display_name = models.CharField(
        verbose_name="PRK escrow location display name",
        max_length=256,
    )
    at_login_only = models.BooleanField(
        verbose_name="Defer enablement at login only",
        default=False,
        help_text="Do not ask for FileVault to be enabled at logout."
    )
    bypass_attempts = models.IntegerField(
        verbose_name="Max bypass attempts at login",
        validators=[MinValueValidator(-1), MaxValueValidator(9999)],
        default=-1,
        help_text="After this number, FileVault will have to be enabled at login."
    )
    show_recovery_key = models.BooleanField(
        verbose_name="Show recovery key",
        default=False,
        help_text="Display the PRK to the user after FileVault is enabled.",
    )
    destroy_key_on_standby = models.BooleanField(
        verbose_name="Destroy key on standby",
        default=False,
        help_text="Force FileVault unlock after hibernation.",
    )
    prk_rotation_interval_days = models.IntegerField(
        verbose_name="PRK rotation interval (days)",
        validators=[MinValueValidator(0), MaxValueValidator(366)],
        default=0,
        help_text="Interval in days after which the PRK will be automatically rotated and escrowed to Zentral."
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = FileVaultConfigManager()

    class Meta:
        ordering = ("name",)
        verbose_name = "filevault config"

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("mdm:filevault_config", args=(self.pk,))

    @property
    def uuid(self):
        h = hashlib.md5(f"{self.pk}|{self.name}|{self.escrow_location_display_name}|"
                        f"{self.at_login_only}|{self.bypass_attempts}|{self.show_recovery_key}|"
                        f"{self.destroy_key_on_standby}|{self.prk_rotation_interval_days}".encode("utf-8"))
        return uuid.UUID(hex=h.hexdigest())

    def can_be_deleted(self):
        return FileVaultConfig.objects.can_be_deleted().filter(pk=self.pk).exists()

    def serialize_for_event(self, keys_only=False):
        d = {"pk": self.pk, "name": self.name}
        if keys_only:
            return d
        d.update({
            "escrow_location_display_name": self.escrow_location_display_name,
            "at_login_only": self.at_login_only,
            "bypass_attempts": self.bypass_attempts,
            "show_recovery_key": self.show_recovery_key,
            "destroy_key_on_standby": self.destroy_key_on_standby,
            "prk_rotation_interval_days": self.prk_rotation_interval_days,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        })
        return d


# Recovery password


class RecoveryPasswordConfigManager(models.Manager):
    def can_be_deleted(self):
        return self.annotate(bp_count=Count("blueprint")).filter(bp_count=0)


class RecoveryPasswordConfig(models.Model):
    name = models.CharField(max_length=256, unique=True)
    dynamic_password = models.BooleanField(default=True)
    static_password = models.TextField(null=True, editable=False)
    rotation_interval_days = models.IntegerField(
        verbose_name="Rotation interval (days)",
        validators=[MinValueValidator(0), MaxValueValidator(366)],
        default=0,
        help_text="Interval in days after which the recovery password will be automatically rotated."
    )
    rotate_firmware_password = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = FileVaultConfigManager()

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("mdm:recovery_password_config", args=(self.pk,))

    def can_be_deleted(self):
        return RecoveryPasswordConfig.objects.can_be_deleted().filter(pk=self.pk).exists()

    def _get_secret_engine_kwargs(self, field):
        return {
            "model": "mdm.recoverypasswordconfig",
            "pk": self.pk,
            "field": field
        }

    def get_static_password(self):
        if not self.static_password:
            return
        return decrypt_str(self.static_password, **self._get_secret_engine_kwargs("static_password"))

    def set_static_password(self, static_password):
        if static_password is None:
            self.static_password = None
            return
        self.static_password = encrypt_str(static_password, **self._get_secret_engine_kwargs("static_password"))

    def rewrap_secrets(self):
        self.server_token = rewrap(self.static_password, **self._get_secret_engine_kwargs("static_password"))

    def serialize_for_event(self, keys_only=False):
        d = {"pk": self.pk, "name": self.name}
        if keys_only:
            return d
        d.update({
            "dynamic_password": self.dynamic_password,
            "rotation_interval_days": self.rotation_interval_days,
            "rotate_firmware_password": self.rotate_firmware_password,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        })
        return d


# Software update enforcement


class SoftwareUpdateEnforcementManager(models.Manager):
    def can_be_deleted(self):
        return self.annotate(bp_count=Count("blueprint")).filter(bp_count=0)


class SoftwareUpdateEnforcement(models.Model):
    name = models.CharField(max_length=256, unique=True)
    details_url = models.URLField(
        verbose_name="Details URL",
        help_text="The URL of a web page that shows details that the organization provides about the enforced update.",
        blank=True
    )
    platforms = ArrayField(models.CharField(max_length=64, choices=Platform.choices))
    tags = models.ManyToManyField(Tag, blank=True)
    # static enforcement
    os_version = models.CharField(
        verbose_name="Target OS version",
        help_text="The target OS version to update the device to by the appropriate time.",
        max_length=32,
        blank=True,
    )
    build_version = models.CharField(
        verbose_name="Target build version",
        help_text="The target build version to update the device to by the appropriate time, for example, 20A242.",
        max_length=32,
        blank=True,
    )
    local_datetime = models.DateTimeField(
        verbose_name="Target local date time",
        help_text="If the user doesn’t trigger the software update before this time, the device force installs it.",
        null=True, blank=True
    )
    # or sliding enforcement window …
    max_os_version = models.CharField(
        verbose_name="Maximum target OS version",
        help_text="The maximum target OS version to update the device to by the appropriate time.",
        max_length=32,
        blank=True,
    )
    delay_days = models.IntegerField(
        verbose_name="Delay in days",
        help_text="Number of days after a software update release before the device force installs it.",
        default=14,
        validators=[MinValueValidator(0), MaxValueValidator(120)],
        null=True, blank=True,
    )
    local_time = models.TimeField(
        verbose_name="Target local time",
        help_text="The local time value that specifies when to force install the software update.",
        default=datetime.time(9, 30),
        null=True, blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = SoftwareUpdateEnforcementManager()

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("mdm:software_update_enforcement", args=(self.pk,))

    def can_be_deleted(self):
        return SoftwareUpdateEnforcement.objects.can_be_deleted().filter(pk=self.pk).exists()

    def serialize_for_event(self, keys_only=False):
        d = {"pk": self.pk, "name": self.name}
        if keys_only:
            return d
        d.update({
            "platforms": self.platforms,
            "tags": [t.serialize_for_event(keys_only=True)
                     for t in self.tags.select_related("taxonomy", "meta_business_unit").all().order_by("pk")],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        })
        for attr in ("details_url",
                     "os_version", "build_version", "local_datetime",
                     "max_os_version", "delay_days", "local_time",):
            val = getattr(self, attr)
            if val is not None and val != "":
                if "time" in attr:
                    val = naive_truncated_isoformat(val)
                d[attr] = val
        return d


# Blueprint


class BlueprintManager(models.Manager):
    def can_be_deleted(self):
        return self.annotate(
            bpa_count=Count("blueprintartifact"),
            da_count=Count("blueprintartifact__artifact__artifactversion__deviceartifact"),
            ua_count=Count("blueprintartifact__artifact__artifactversion__userartifact"),
            dc_count=Count("blueprintartifact__artifact__artifactversion__devicecommand"),
            uc_count=Count("blueprintartifact__artifact__artifactversion__usercommand"),
        ).filter(
            bpa_count=0,
            da_count=0,
            ua_count=0,
            dc_count=0,
            uc_count=0,
        )


class Blueprint(models.Model):

    class InventoryItemCollectionOption(models.IntegerChoices):
        NO = 0
        MANAGED_ONLY = 1
        ALL = 2

    name = models.CharField(max_length=256, unique=True)

    serialized_artifacts = models.JSONField(default=dict, editable=False)

    # inventory
    inventory_interval = models.IntegerField(
        default=86400,
        validators=[MinValueValidator(14400), MaxValueValidator(604800)],
        help_text="In seconds, the minimum interval between two inventory collection. "
                  "Minimum 4h, maximum 7d, default 1d."
    )
    collect_apps = models.IntegerField(
        choices=InventoryItemCollectionOption.choices,
        default=InventoryItemCollectionOption.NO
    )
    collect_certificates = models.IntegerField(
        choices=InventoryItemCollectionOption.choices,
        default=InventoryItemCollectionOption.NO
    )
    collect_profiles = models.IntegerField(
        choices=InventoryItemCollectionOption.choices,
        default=InventoryItemCollectionOption.NO
    )
    # FileVault
    filevault_config = models.ForeignKey(FileVaultConfig, null=True, blank=True,
                                         on_delete=models.SET_NULL)
    # Recovery password
    recovery_password_config = models.ForeignKey(RecoveryPasswordConfig, null=True, blank=True,
                                                 on_delete=models.SET_NULL)

    # Software update enforcements
    software_update_enforcements = models.ManyToManyField(SoftwareUpdateEnforcement, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = BlueprintManager()

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("mdm:blueprint", args=(self.pk,))

    def get_inventory_interval_display(self):
        now = datetime.datetime.utcnow()
        return timesince(now - datetime.timedelta(seconds=self.inventory_interval), now=now)

    def _get_inventory_item_collection_option_display(self, attr):
        return self.InventoryItemCollectionOption(getattr(self, attr)).name

    def get_collect_apps_display(self):
        return self._get_inventory_item_collection_option_display("collect_apps")

    def get_collect_certificates_display(self):
        return self._get_inventory_item_collection_option_display("collect_certificates")

    def get_collect_profiles_display(self):
        return self._get_inventory_item_collection_option_display("collect_profiles")

    def serialize_for_event(self, keys_only=False):
        d = {"pk": self.pk, "name": self.name}
        if keys_only:
            return d
        d.update({
            "inventory_interval": self.inventory_interval,
            "collect_apps": self.get_collect_apps_display(),
            "collect_certificates": self.get_collect_certificates_display(),
            "collect_profiles": self.get_collect_profiles_display(),
            "created_at": self.created_at,
            "updated_at": self.updated_at
        })
        if self.filevault_config:
            d["filevault_config"] = self.filevault_config.serialize_for_event(keys_only=True)
        if self.recovery_password_config:
            d["recovery_password_config"] = self.recovery_password_config.serialize_for_event(keys_only=True)
        sues = [sue.serialize_for_event(keys_only=True)
                for sue in self.software_update_enforcements.order_by("name")]
        if sues:
            d["software_update_enforcements"] = sues
        return d

    def can_be_deleted(self):
        return Blueprint.objects.can_be_deleted().filter(pk=self.pk).count() == 1


# SCEP


class SCEPConfig(models.Model):
    provisioning_uid = models.CharField(max_length=256, unique=True, null=True, editable=False)
    name = models.CharField(max_length=256, unique=True)
    url = models.URLField()
    key_usage = models.IntegerField(choices=((0, 'None (0)'),
                                             (1, 'Signing (1)'),
                                             (4, 'Encryption (4)'),
                                             (5, 'Signing & Encryption (1 | 4 = 5)')),
                                    default=0,
                                    help_text="A bitmask indicating the use of the key.")
    key_is_extractable = models.BooleanField(default=False,
                                             help_text="If true, the private key can be exported from the keychain.")
    keysize = models.IntegerField(choices=((1024, '1024-bit'),
                                           (2048, '2048-bit'),
                                           (4096, '4096-bit')),
                                  default=2048)
    allow_all_apps_access = models.BooleanField(default=False,
                                                help_text="If true, all apps have access to the private key.")
    challenge_type = models.CharField(max_length=64, choices=SCEPChallengeType.choices())
    challenge_kwargs = models.JSONField(editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("mdm:scep_config", args=(self.pk,))

    def get_challenge_kwargs(self):
        challenge = load_scep_challenge(self)
        return challenge.get_kwargs()

    def set_challenge_kwargs(self, kwargs):
        challenge = get_scep_challenge(self)
        challenge.set_kwargs(kwargs)

    def rewrap_secrets(self):
        challenge = load_scep_challenge(self)
        challenge.rewrap_kwargs()

    def can_be_deleted(self):
        return (
            self.provisioning_uid is None
            and self.depenrollment_set.count() == 0
            and self.otaenrollment_set.count() == 0
            and self.userenrollment_set.count() == 0
        )

    def can_be_updated(self):
        return self.provisioning_uid is None

    def _get_CHALLENGE_TYPE_challenge_kwargs(self, challenge_type):
        if self.challenge_type == challenge_type.name:
            return self.get_challenge_kwargs()

    def __getattr__(self, name):
        for challenge_type in SCEPChallengeType:
            if name == f"get_{challenge_type.name.lower()}_challenge_kwargs":
                return partial(self._get_CHALLENGE_TYPE_challenge_kwargs, challenge_type)
        raise AttributeError


# Apps and (not!) Books
# https://developer.apple.com/documentation/devicemanagement/app_and_book_management


def hash_location_notification_auth_token(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


class LocationManager(models.Manager):
    def get_with_mdm_info_id_and_token(self, mdm_info_id, token):
        return self.get(
            mdm_info_id=mdm_info_id,
            notification_auth_token_hash=hash_location_notification_auth_token(token)
        )


class Location(models.Model):
    # token info
    server_token_hash = models.CharField(max_length=40, unique=True)
    server_token = models.TextField(null=True)
    server_token_expiration_date = models.DateTimeField()
    organization_name = models.TextField()

    # client info
    name = models.TextField()
    country_code = models.CharField(max_length=2)
    library_uid = models.TextField()
    platform = models.TextField()
    website_url = models.URLField()

    # set by Zentral, to authenticate the Apple notification requests
    mdm_info_id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    notification_auth_token_hash = models.CharField(max_length=64, editable=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = LocationManager()

    class Meta:
        ordering = ("name", "organization_name")

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("mdm:location", args=(self.pk,))

    def serialize_for_event(self, keys_only=True):
        d = {
            "pk": self.pk,
            "mdm_info_id": self.mdm_info_id,
        }
        if not keys_only:
            d.update({
                "server_token_expiration_date": self.server_token_expiration_date,
                "organization_name": self.organization_name,
                "country_code": self.country_code,
                "library_uid": self.library_uid,
                "name": self.name,
                "platform": self.platform,
                "website_url": self.website_url,
            })
        return d

    def server_token_expires_soon(self):
        # TODO: hard coded 15 days
        return self.server_token_expiration_date <= timezone.now() + datetime.timedelta(days=15)

    def can_be_deleted(self):
        # TODO: optmize?
        return self.locationasset_set.count() == 0

    # secret

    def get_server_token(self):
        assert self.pk, "Location must have a PK"
        return decrypt_str(self.server_token, field="server_token", model="mdm.location", pk=self.pk)

    def set_server_token(self, server_token):
        assert self.pk, "Location must have a PK"
        self.server_token = encrypt_str(server_token, field="server_token", model="mdm.location", pk=self.pk)

    def rewrap_secrets(self):
        assert self.pk, "Location must have a PK"
        self.server_token = rewrap(self.server_token, field="server_token", model="mdm.location", pk=self.pk)

    # auth token

    def set_notification_auth_token(self):
        notification_auth_token = "ztl_mdm_nat_{}".format(get_random_string(22))  # 22 ~ 131 bits
        self.notification_auth_token_hash = hash_location_notification_auth_token(notification_auth_token)
        return notification_auth_token


class Asset(models.Model):

    class ProductType(models.TextChoices):
        APP = "App"
        BOOK = "Book"

    adam_id = models.CharField(max_length=64)
    pricing_param = models.CharField(max_length=16)

    product_type = models.CharField(max_length=4, choices=ProductType.choices)
    device_assignable = models.BooleanField()
    revocable = models.BooleanField()
    supported_platforms = ArrayField(models.CharField(max_length=64, choices=Platform.choices))

    metadata = models.JSONField(null=True)
    name = models.TextField(null=True)
    bundle_id = models.TextField(null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (("adam_id", "pricing_param"),)

    def __str__(self):
        if self.name:
            return f"{self.product_type} {self.name}"
        else:
            return f"{self.product_type} {self.adam_id} {self.pricing_param}"

    def get_absolute_url(self):
        return reverse("mdm:asset", args=(self.pk,))

    def serialize_for_event(self, keys_only=True):
        d = {
            "pk": self.pk,
            "adam_id": self.adam_id,
            "pricing_param": self.pricing_param,
        }
        if not keys_only:
            for attr in ("product_type", "device_assignable", "revocable", "supported_platforms", "name", "bundle_id"):
                val = getattr(self, attr)
                if val:
                    d[attr] = val
        return d

    @cached_property
    def icon_url(self):
        if not self.metadata:
            return
        artwork = self.metadata.get("artwork")
        if not artwork:
            return
        width = artwork.get("width")
        height = artwork.get("height")
        url = artwork.get("url")
        if isinstance(width, int) and isinstance(height, int) and url:
            return url.format(w=min(width, 128), h=min(height, 128), f="png")

    @cached_property
    def store_url(self):
        if not self.metadata:
            return
        return self.metadata.get("url")

    @cached_property
    def lastest_version(self):
        if not self.metadata:
            return
        max_version = None
        for offer in self.metadata.get("offers", []):
            try:
                version = tuple(int(s) for s in offer["version"]["display"].split("."))
            except (KeyError, TypeError, ValueError):
                # TODO: better
                pass
            else:
                if max_version is None or max_version < version:
                    max_version = version
        if max_version:
            return ".".join(str(i) for i in max_version)

    def get_artifacts_store_apps(self):
        artifacts = []
        current_artifact = None
        current_store_apps = []
        for store_app in (
            StoreApp.objects
                    .select_related("location_asset__location",
                                    "location_asset__asset",
                                    "artifact_version__artifact")
                    .filter(location_asset__asset=self)
                    .order_by("artifact_version__artifact__name",
                              "artifact_version__version")
        ):
            artifact = store_app.artifact_version.artifact
            if current_artifact and artifact != current_artifact:
                artifacts.append((current_artifact, current_store_apps))
                current_store_apps = []
            current_artifact = artifact
            current_store_apps.append(store_app)
        if current_store_apps:
            artifacts.append((current_artifact, current_store_apps))
        return artifacts


class LocationAsset(models.Model):
    count_attrs = (
        "assigned_count",
        "available_count",
        "retired_count",
        "total_count",
    )

    location = models.ForeignKey(Location, on_delete=models.CASCADE)
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE)

    assigned_count = models.IntegerField(default=0)
    available_count = models.IntegerField(default=0)
    retired_count = models.IntegerField(default=0)
    total_count = models.IntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (("asset", "location"),)

    def __str__(self):
        return f"{self.location} - {self.asset}"

    def get_absolute_url(self):
        return "{}#la-{}".format(self.asset.get_absolute_url(), self.pk)

    def serialize_for_event(self, keys_only=True, location=None, asset=None):
        location = location or self.location
        asset = asset or self.asset
        d = {
            "location": location.serialize_for_event(keys_only=True),
            "asset": asset.serialize_for_event(keys_only=True),
        }
        if not keys_only:
            for attr in self.count_attrs:
                d[attr] = getattr(self, attr)
        return d

    def get_availability_incident_severity(self):
        if self.total_count > 0:
            incident_update_severity = Severity.NONE
            availability_perc = self.available_count / self.total_count
            if availability_perc <= 0.1:  # TODO hard-coded
                incident_update_severity = Severity.MAJOR
            elif availability_perc <= 0.2:  # TODO hard-coded
                incident_update_severity = Severity.MINOR
            return incident_update_severity

    def count_errors(self):
        errors = []
        for attr in self.count_attrs:
            if getattr(self, attr) < 0:
                errors.append("{} < 0".format(attr.replace("_", " ")))
        if self.assigned_count > self.total_count:
            errors.append("assigned count > total count")
        if self.available_count > self.total_count:
            errors.append("available count > total count")
        return errors


class DeviceAssignment(models.Model):
    location_asset = models.ForeignKey(LocationAsset, on_delete=models.CASCADE)
    serial_number = models.TextField(db_index=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = (("location_asset", "serial_number"),)


# Enrollment


class EnrolledDeviceManager(models.Manager):
    def blocked(self):
        return self.filter(blocked_at__isnull=False)

    def allowed(self):
        return self.filter(blocked_at__isnull=True)


class EnrolledDevice(models.Model):
    # device info
    udid = models.CharField(max_length=255, unique=True)
    enrollment_id = models.TextField(null=True)
    serial_number = models.TextField(db_index=True)
    name = models.TextField(null=True)
    model = models.TextField(null=True)
    platform = models.CharField(max_length=64, choices=Platform.choices)
    os_version = models.CharField(max_length=64, null=True)
    os_version_extra = models.CharField(max_length=32, null=True)
    build_version = models.CharField(max_length=32, null=True)
    build_version_extra = models.CharField(max_length=32, null=True)
    apple_silicon = models.BooleanField(null=True)

    # notifications
    push_certificate = models.ForeignKey(PushCertificate, on_delete=models.PROTECT)
    token = models.BinaryField(blank=True, null=True)
    push_magic = models.TextField(blank=True, null=True)
    last_seen_at = models.DateTimeField(null=True)
    last_notified_at = models.DateTimeField(null=True)
    notification_queued_at = models.DateTimeField(null=True)

    # tokens
    unlock_token = models.TextField(null=True)
    bootstrap_token = models.TextField(null=True)

    # cert
    cert_fingerprint = models.BinaryField(blank=True, null=True)
    cert_not_valid_after = models.DateTimeField(blank=True, null=True)

    # artifacts
    blueprint = models.ForeignKey(Blueprint, on_delete=models.SET_NULL, blank=True, null=True)
    awaiting_configuration = models.BooleanField(null=True)

    # declarative management
    declarative_management = models.BooleanField(default=False)
    declarations_token = models.CharField(max_length=40, default="")
    client_capabilities = models.JSONField(null=True)

    # information
    device_information = models.JSONField(null=True)
    device_information_updated_at = models.DateTimeField(null=True)
    security_info = models.JSONField(null=True)
    security_info_updated_at = models.DateTimeField(null=True)
    apps_updated_at = models.DateTimeField(null=True)
    certificates_updated_at = models.DateTimeField(null=True)
    profiles_updated_at = models.DateTimeField(null=True)
    # denormalized attributes
    # enrollment
    dep_enrollment = models.BooleanField(null=True)
    user_enrollment = models.BooleanField(null=True)
    user_approved_enrollment = models.BooleanField(null=True)
    supervised = models.BooleanField(null=True)
    # bootstrap token
    bootstrap_token_allowed_for_authentication = models.BooleanField(null=True)
    bootstrap_token_required_for_software_update = models.BooleanField(null=True)
    bootstrap_token_required_for_kext_approval = models.BooleanField(null=True)
    # activation lock
    activation_lock_manageable = models.BooleanField(null=True)

    # FileVault
    filevault_config_uuid = models.UUIDField(null=True)
    filevault_escrow_key = models.TextField(null=True)
    filevault_prk = models.TextField(null=True)
    filevault_prk_updated_at = models.DateTimeField(null=True)

    # Recovery password
    recovery_password = models.TextField(null=True)
    recovery_password_updated_at = models.DateTimeField(null=True)
    pending_firmware_password = models.TextField(null=True)
    pending_firmware_password_created_at = models.DateTimeField(null=True)

    # timestamps
    checkout_at = models.DateTimeField(blank=True, null=True)
    blocked_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = EnrolledDeviceManager()

    def __str__(self):
        return self.udid

    def get_absolute_url(self):
        return reverse("mdm:enrolled_device", args=(self.pk,))

    class Meta:
        permissions = [
            ("view_filevault_prk", "Can view FileVault PRK"),
            ("view_recovery_password", "Can view recovery password"),
        ]

    # secrets

    def _get_secret_engine_kwargs(self, field):
        if not self.udid:
            raise ValueError("EnrolledDevice must have a UDID")
        return {"field": field, "model": "mdm.enrolleddevice", "udid": self.udid}

    def get_bootstrap_token(self):
        if not self.bootstrap_token:
            return
        return decrypt(self.bootstrap_token, **self._get_secret_engine_kwargs("bootstrap_token"))

    def set_bootstrap_token(self, token):
        if token is None:
            self.bootstrap_token = None
            return
        self.bootstrap_token = encrypt(token, **self._get_secret_engine_kwargs("bootstrap_token"))

    def get_unlock_token(self):
        if not self.unlock_token:
            return
        return decrypt(self.unlock_token, **self._get_secret_engine_kwargs("unlock_token"))

    def set_unlock_token(self, token):
        if token is None:
            self.unlock_token = None
            return
        self.unlock_token = encrypt(token, **self._get_secret_engine_kwargs("unlock_token"))

    def get_filevault_escrow_key(self):
        if not self.filevault_escrow_key:
            return
        return decrypt(self.filevault_escrow_key, **self._get_secret_engine_kwargs("filevault_escrow_key"))

    def set_filevault_escrow_key(self, filevault_escrow_key):
        if filevault_escrow_key is None:
            self.filevault_escrow_key = None
            return
        self.filevault_escrow_key = encrypt(filevault_escrow_key,
                                            **self._get_secret_engine_kwargs("filevault_escrow_key"))

    def get_filevault_prk(self):
        if not self.filevault_prk:
            return
        return decrypt_str(self.filevault_prk, **self._get_secret_engine_kwargs("filevault_prk"))

    def set_filevault_prk(self, filevault_prk):
        if filevault_prk is None:
            self.filevault_prk = None
            return
        self.filevault_prk = encrypt_str(filevault_prk, **self._get_secret_engine_kwargs("filevault_prk"))
        self.filevault_prk_updated_at = datetime.datetime.utcnow()

    def get_recovery_password(self):
        if not self.recovery_password:
            return
        return decrypt_str(self.recovery_password, **self._get_secret_engine_kwargs("recovery_password"))

    def set_recovery_password(self, recovery_password):
        if not recovery_password:
            self.recovery_password = None
            return
        self.recovery_password = encrypt_str(recovery_password, **self._get_secret_engine_kwargs("recovery_password"))
        self.recovery_password_updated_at = datetime.datetime.utcnow()

    def get_pending_firmware_password(self):
        if not self.pending_firmware_password:
            return
        return decrypt_str(self.pending_firmware_password,
                           **self._get_secret_engine_kwargs("pending_firmware_password"))

    def set_pending_firmware_password(self, pending_firmware_password):
        if pending_firmware_password is None:
            self.pending_firmware_password = None
            self.pending_firmware_password_created_at = None
            return
        self.pending_firmware_password = encrypt_str(
            pending_firmware_password,
            **self._get_secret_engine_kwargs("pending_firmware_password")
        )
        self.pending_firmware_password_created_at = datetime.datetime.utcnow()

    def rewrap_secrets(self):
        if self.bootstrap_token:
            self.bootstrap_token = rewrap(self.bootstrap_token, **self._get_secret_engine_kwargs("bootstrap_token"))
        if self.unlock_token:
            self.unlock_token = rewrap(self.unlock_token, **self._get_secret_engine_kwargs("unlock_token"))
        if self.filevault_escrow_key:
            self.filevault_escrow_key = rewrap(self.filevault_escrow_key,
                                               **self._get_secret_engine_kwargs("filevault_escrow_key"))
        if self.filevault_prk:
            self.filevault_prk = rewrap(self.filevault_prk, **self._get_secret_engine_kwargs("filevault_prk"))
        if self.recovery_password:
            self.recovery_password = rewrap(self.recovery_password,
                                            **self._get_secret_engine_kwargs("recovery_password"))
        if self.pending_firmware_password:
            self.pending_firmware_password = rewrap(self.pending_firmware_password,
                                                    **self._get_secret_engine_kwargs("pending_firmware_password"))

    def get_urlsafe_serial_number(self):
        if self.serial_number:
            return MetaMachine(self.serial_number).get_urlsafe_serial_number()

    def block(self):
        if not self.blocked_at:
            self.blocked_at = datetime.datetime.utcnow()
            self.save()

    def unblock(self):
        if self.blocked_at:
            self.blocked_at = None
            self.save()

    def purge_state(self, full=False):
        self.declarative_management = False
        self.last_seen_at = None
        self.last_notified_at = None
        self.notification_queued_at = None
        self.device_information_updated_at = None
        self.security_info_updated_at = None
        self.apps_updated_at = None
        self.certificates_updated_at = None
        self.profiles_updated_at = None
        self.dep_enrollment = None
        self.user_enrollment = None
        self.user_approved_enrollment = None
        self.supervised = None
        self.filevault_escrow_key = None
        self.filevault_config_uuid = None
        if full:
            self.checkout_at = None
            self.blocked_at = None
        self.save()
        self.commands.all().delete()
        self.target_artifacts.all().delete()
        self.enrolleduser_set.all().delete()
        # TODO purge tokens?
        # TODO revoke assets?

    def do_checkout(self):
        self.token = self.push_magic = self.bootstrap_token = self.unlock_token = None
        self.checkout_at = timezone.now()
        self.purge_state()
        self.save()

    def can_be_poked(self):
        now = timezone.now()
        return (
            self.checkout_at is None
            and self.push_certificate is not None
            and self.push_certificate.certificate is not None
            and self.push_certificate.not_before < now
            and now < self.push_certificate.not_after
            and self.token is not None
            and self.push_magic is not None
        )

    @property
    def comparable_os_version(self):
        return (
            *make_comparable_os_version(self.os_version),
            self.os_version_extra or ""
        )

    @property
    def full_os_version(self):
        items = []
        if self.os_version:
            items.append(self.os_version)
        if self.os_version_extra:
            items.append(self.os_version_extra)
        if self.build_version_extra:
            items.append(f"({self.build_version_extra})")
        elif self.build_version:
            items.append(f"({self.build_version})")
        return " ".join(items)

    @property
    def current_os_version(self):
        return " ".join(s for s in (self.os_version, self.os_version_extra) if s)

    @property
    def current_build_version(self):
        return self.build_version_extra or self.build_version or ""

    def get_architecture_for_display(self):
        if self.apple_silicon:
            return "Apple silicon"
        elif self.apple_silicon is False and self.platform == Platform.MACOS:
            return "Intel"

    def iter_enrollment_session_info(self):
        query = (
            "WITH sessions AS ("
            "  SELECT 'DEP' session_type, s.id, s.realm_user_id, s.status, s.updated_at, s.created_at,"
            "  'DEP' enrollment_type, e.name enrollment_name, e.id enrollment_id"
            "  FROM mdm_depenrollmentsession s"
            "  JOIN mdm_depenrollment e ON (s.dep_enrollment_id = e.id)"
            "  WHERE s.enrolled_device_id = %s "

            "UNION"

            "  SELECT 'OTA' session_type, s.id, s.realm_user_id, s.status, s.updated_at, s.created_at,"
            "  'OTA' enrollment_type, e.name enrollment_name, e.id enrollment_id"
            "  FROM mdm_otaenrollmentsession s"
            "  JOIN mdm_otaenrollment e ON (s.ota_enrollment_id = e.id)"
            "  WHERE s.enrolled_device_id = %s "

            "UNION"

            "  SELECT 'RE' session_type, s.id, s.realm_user_id, s.status, s.updated_at, s.created_at,"
            "  CASE"
            "  WHEN d.id IS NOT NULL THEN 'DEP'"
            "  WHEN o.id IS NOT NULL THEN 'OTA'"
            "  WHEN u.id IS NOT NULL THEN 'USER'"
            "  END enrollment_type,"
            "  COALESCE(d.name, o.name, u.name) enrollment_name,"
            "  COALESCE(d.id, o.id, u.id) enrollment_id"
            "  FROM mdm_reenrollmentsession s"
            "  LEFT JOIN mdm_depenrollment d ON (s.dep_enrollment_id = d.id)"
            "  LEFT JOIN mdm_otaenrollment o ON (s.ota_enrollment_id = o.id)"
            "  LEFT JOIN mdm_userenrollment u ON (s.user_enrollment_id = u.id)"
            "  WHERE s.enrolled_device_id = %s "

            "UNION"

            "  SELECT 'USER' session_type, s.id, s.realm_user_id, s.status, s.updated_at, s.created_at,"
            "  'USER' enrollment_type, e.name enrollment_name, e.id enrollment_id"
            "  FROM mdm_userenrollmentsession s"
            "  JOIN mdm_userenrollment e ON (s.user_enrollment_id = e.id)"
            "  WHERE s.enrolled_device_id = %s"
            ") SELECT s.*,  u.username realm_username "
            "FROM sessions s "
            "LEFT JOIN realms_realmuser u ON (s.realm_user_id = u.uuid) "
            "ORDER BY s.created_at DESC;"
        )
        cursor = connection.cursor()
        cursor.execute(query, [self.pk, self.pk, self.pk, self.pk])
        columns = [c.name for c in cursor.description]
        for t in cursor.fetchall():
            yield dict(zip(columns, t))

    @property
    def bootstrap_token_escrowed(self):
        if self.bootstrap_token:
            return True
        return False

    @property
    def filevault_enabled(self):
        try:
            return self.security_info["FDE_Enabled"]
        except (KeyError, TypeError):
            pass

    @property
    def filevault_prk_escrowed(self):
        if self.filevault_prk:
            return True
        return False

    @property
    def recovery_password_escrowed(self):
        if self.recovery_password:
            return True
        return False


class EnrolledUser(models.Model):
    enrolled_device = models.ForeignKey(EnrolledDevice, on_delete=models.CASCADE)

    # user info
    user_id = models.CharField(max_length=255, unique=True)
    enrollment_id = models.TextField(null=True)
    long_name = models.TextField()
    short_name = models.TextField()

    # declarative management
    declarative_management = models.BooleanField(default=False)
    declarations_token = models.CharField(max_length=40, default="")
    client_capabilities = models.JSONField(null=True)

    # notifications
    token = models.BinaryField()
    last_seen_at = models.DateTimeField(null=True)
    last_notified_at = models.DateTimeField(null=True)
    notification_queued_at = models.DateTimeField(null=True)

    # timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.long_name or self.short_name

    def get_absolute_url(self):
        return reverse("mdm:enrolled_user", args=(self.enrolled_device.pk, self.pk,))


# Common base model for the DEP, OTA and user enrollment sessions


class EnrollmentSession(models.Model):
    realm_user = models.ForeignKey(RealmUser, on_delete=models.PROTECT, blank=True, null=True)
    enrolled_device = models.ForeignKey(EnrolledDevice, on_delete=models.CASCADE, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

    def get_common_name(self):
        return "{prefix}${secret}".format(prefix=self.get_prefix(),
                                          secret=self.enrollment_secret.secret)

    def get_organization(self):
        return "MBU${}".format(self.enrollment_secret.meta_business_unit.pk)

    def get_serial_number(self):
        try:
            return self.enrollment_secret.serial_numbers[0]
        except (IndexError, TypeError):
            pass

    def get_urlsafe_serial_number(self):
        serial_number = self.get_serial_number()
        if serial_number:
            return MetaMachine(serial_number).get_urlsafe_serial_number()

    def is_completed(self):
        return self.status == self.COMPLETED

    def serialize_for_event(self, enrollment_session_type, extra_dict):
        d = {"pk": self.pk,
             "type": enrollment_session_type,
             "status": self.status}
        return {"enrollment_session": d}

    # status update methods

    def _set_next_status(self, next_status, test, **update_dict):
        if test:
            update_fields = ["status", "updated_at"]
            self.status = next_status
            for attr, val in update_dict.items():
                update_fields.append(attr)
                setattr(self, attr, val)
            self.save(update_fields=update_fields)
        else:
            raise EnrollmentSessionStatusError(self, next_status)

    @property
    def device_enrolled_at(self):
        return self.created_at


class RealmGroupTagMapping(models.Model):
    realm_group = models.ForeignKey(RealmGroup, on_delete=models.CASCADE, verbose_name="Group")
    tag = models.ForeignKey(Tag, on_delete=models.CASCADE)

    class Meta:
        unique_together = (("realm_group", "tag"),)

    def __str__(self):
        return f"{self.realm_group} → {self.tag}"

    def get_absolute_url(self):
        return reverse("mdm:realm_group_tag_mappings") + f"#rgtm-{self.pk}"


class EnrollmentCustomViewManager(models.Manager):
    def can_be_deleted(self):
        return self.annotate(
            decv_count=Count("depenrollmentcustomview"),
        ).filter(
            decv_count=0,
        )


class EnrollmentCustomView(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(unique=True)
    description = models.TextField(blank=True)
    html = models.TextField(verbose_name="HTML template")
    requires_authentication = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = EnrollmentCustomViewManager()

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("mdm:enrollment_custom_view", args=(self.pk,))

    def can_be_deleted(self):
        return EnrollmentCustomView.objects.can_be_deleted().filter(pk=self.pk).exists()

    def serialize_for_event(self, keys_only=False):
        d = {
            "pk": str(self.pk),
            "name": self.name,
        }
        if keys_only:
            return d
        d.update({
            "description": self.description,
            "html": self.html,
            "requires_authentication": self.requires_authentication,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        })
        return d


# Abstract MDM enrollment model


class MDMEnrollment(models.Model):
    display_name = models.CharField(max_length=128, default="Zentral MDM",  # ! Terraform Provider default value too !
                                    help_text="Name displayed in the device settings")
    push_certificate = models.ForeignKey(PushCertificate, on_delete=models.PROTECT)

    scep_config = models.ForeignKey(SCEPConfig, on_delete=models.PROTECT)
    scep_verification = models.BooleanField(
        default=False,
        help_text="Set to true if the SCEP service is configured to post the CSR to Zentral for verification. "
                  "If true, successful verifications will be required during the enrollments."
    )

    blueprint = models.ForeignKey(Blueprint, on_delete=models.SET_NULL, blank=True, null=True)

    # linked to an auth realm
    # if linked, a user has to authenticate to get the mdm payload.
    realm = models.ForeignKey(Realm, on_delete=models.PROTECT, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

    def can_be_deleted(self):
        raise NotImplementedError

    def delete(self, *args, **kwargs):
        if self.can_be_deleted():
            self.enrollment_secret.delete()
            super().delete(*args, **kwargs)
        else:
            raise ValueError(f"{self.__class__.__name__} {self.pk} cannot be deleted")

    def serialize_for_event(self):
        return {
            "pk": self.pk,
            "name": self.name,
            "realm": self.realm.serialize_for_event(keys_only=True) if self.realm else None,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }


# OTA Enrollment


class OTAEnrollment(MDMEnrollment):
    name = models.CharField(max_length=256, unique=True)
    enrollment_secret = models.OneToOneField(EnrollmentSecret, on_delete=models.CASCADE,
                                             related_name="ota_enrollment")
    # if linked to an auth realm, a user has to authenticate to get the mdm payload.

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return self.name

    def serialize_for_event(self):
        d = super().serialize_for_event()
        d.update(self.enrollment_secret.serialize_for_event())
        return d

    def get_absolute_url(self):
        return reverse("mdm:ota_enrollment", args=(self.pk,))

    def get_enroll_full_url(self):
        if self.realm:
            return "{}{}".format(settings["api"]["tls_hostname"],
                                 reverse("mdm_public:ota_enrollment_enroll", args=(self.pk,)))

    def revoke(self):
        if not self.enrollment_secret.revoked_at:
            # TODO events
            self.enrollment_secret.revoked_at = timezone.now()
            self.enrollment_secret.save()
            self.save()

    def can_be_deleted(self):
        return self.otaenrollmentsession_set.count() == 0 and self.reenrollmentsession_set.count() == 0


class OTAEnrollmentSessionManager(models.Manager):
    def create_from_realm_user(self, ota_enrollment, realm_user):
        enrollment_secret = ota_enrollment.enrollment_secret
        tags = list(enrollment_secret.tags.all())
        new_es = EnrollmentSecret(
            meta_business_unit=enrollment_secret.meta_business_unit,
            quota=3,  # Verified three times: config profile download + 2 different SCEP payloads
            expired_at=enrollment_secret.expired_at
        )
        new_es.save(secret_length=56)  # CN max 64 - $ separator - prefix, ota or mdm$ota
        new_es.tags.set(tags)
        enrollment_session = self.model(status=self.model.PHASE_1,
                                        ota_enrollment=ota_enrollment,
                                        realm_user=realm_user,
                                        enrollment_secret=new_es)
        enrollment_session.save()
        return enrollment_session

    def create_from_machine_info(self, ota_enrollment, serial_number, udid):
        # Build a new secret that can be used only by one specific machine
        enrollment_secret = ota_enrollment.enrollment_secret
        tags = list(enrollment_secret.tags.all())
        new_es = EnrollmentSecret(
            meta_business_unit=enrollment_secret.meta_business_unit,
            serial_numbers=[serial_number],
            udids=[udid],
            quota=2,  # Verified twice with 2 different SCEP payloads
            expired_at=enrollment_secret.expired_at
        )
        new_es.save(secret_length=56)  # CN max 64 - $ separator - prefix, ota or mdm$ota
        new_es.tags.set(tags)
        return self.create(status=self.model.PHASE_2,
                           ota_enrollment=ota_enrollment,
                           enrollment_secret=new_es)


class OTAEnrollmentSession(EnrollmentSession):
    PHASE_1 = "PHASE_1"
    PHASE_2 = "PHASE_2"
    PHASE_2_SCEP_VERIFIED = "PHASE_2_SCEP_VERIFIED"
    PHASE_3 = "PHASE_3"
    PHASE_3_SCEP_VERIFIED = "PHASE_3_SCEP_VERIFIED"
    AUTHENTICATED = "AUTHENTICATED"
    COMPLETED = "COMPLETED"
    STATUS_CHOICES = (
        (PHASE_1, _("Phase 1")),
        (PHASE_2, _("Phase 2")),
        (PHASE_2_SCEP_VERIFIED, _("Phase 2 SCEP verified")),
        (PHASE_3, _("Phase 3")),
        (PHASE_3_SCEP_VERIFIED, _("Phase 3 SCEP verified")),
        (AUTHENTICATED, _("Authenticated")),  # first MDM Checkin Authenticate call
        (COMPLETED, _("Completed")),  # first MDM Checkin TokenUpdate call
    )
    status = models.CharField(max_length=64, choices=STATUS_CHOICES)
    ota_enrollment = models.ForeignKey(OTAEnrollment, on_delete=models.CASCADE)
    enrollment_secret = models.OneToOneField(EnrollmentSecret, on_delete=models.PROTECT,
                                             related_name="ota_enrollment_session")
    phase2_request = models.ForeignKey(EnrollmentSecretRequest, on_delete=models.PROTECT,
                                       null=True, related_name="+")
    phase2_scep_request = models.ForeignKey(EnrollmentSecretRequest, on_delete=models.PROTECT,
                                            null=True, related_name="+")
    phase3_scep_request = models.ForeignKey(EnrollmentSecretRequest, on_delete=models.PROTECT,
                                            null=True, related_name="+")

    objects = OTAEnrollmentSessionManager()

    def get_enrollment(self):
        return self.ota_enrollment

    def get_prefix(self):
        if self.status == self.PHASE_2:
            return "OTA"
        elif self.status == self.PHASE_3:
            return "MDM$OTA"
        else:
            raise ValueError("Wrong enrollment sessions status")

    def serialize_for_event(self):
        return super().serialize_for_event("ota", {"ota_enrollment": self.ota_enrollment.serialize_for_event()})

    def get_blueprint(self):
        return self.ota_enrollment.blueprint

    # status update methods

    def set_phase2_status(self, es_request, serial_number, udid):
        test = (serial_number
                and udid
                and self.realm_user
                and self.status == self.PHASE_1
                and not self.phase2_request
                and not self.phase2_scep_request
                and not self.phase3_scep_request
                and not self.enrolled_device)
        self._set_next_status(self.PHASE_2, test, phase2_request=es_request)
        # restrict enrollment secret to the current machine
        self.enrollment_secret.serial_numbers = [serial_number]
        self.enrollment_secret.udids = [udid]
        self.enrollment_secret.save()

    def set_phase2_scep_verified_status(self, es_request):
        test = (es_request
                and self.status == self.PHASE_2
                and not self.phase2_scep_request
                and not self.phase3_scep_request
                and not self.enrolled_device)
        self._set_next_status(self.PHASE_2_SCEP_VERIFIED, test, phase2_scep_request=es_request)

    def set_phase3_status(self):
        if self.ota_enrollment.scep_verification:
            allowed_statuses = (self.PHASE_2_SCEP_VERIFIED,)
            scep_ok = self.phase2_scep_request is not None and self.phase3_scep_request is None
        else:
            allowed_statuses = (self.PHASE_2, self.PHASE_2_SCEP_VERIFIED)
            scep_ok = self.phase3_scep_request is None
        test = (
            scep_ok
            and self.status in allowed_statuses
            and not self.enrolled_device
        )
        self._set_next_status(self.PHASE_3, test)

    def set_phase3_scep_verified_status(self, es_request):
        if self.ota_enrollment.scep_verification:
            scep_ok = self.phase2_scep_request is not None and self.phase3_scep_request is None
        else:
            scep_ok = self.phase3_scep_request is None
        test = (es_request
                and scep_ok
                and self.status == self.PHASE_3
                and not self.enrolled_device)
        self._set_next_status(self.PHASE_3_SCEP_VERIFIED, test, phase3_scep_request=es_request)

    def set_authenticated_status(self, enrolled_device):
        if self.ota_enrollment.scep_verification:
            allowed_statuses = (self.PHASE_3_SCEP_VERIFIED,)
            scep_ok = self.phase2_scep_request is not None and self.phase3_scep_request is not None
        else:
            allowed_statuses = (self.PHASE_3, self.PHASE_3_SCEP_VERIFIED)
            scep_ok = True
        test = (enrolled_device
                and scep_ok
                and self.status in allowed_statuses
                and not self.enrolled_device)
        self._set_next_status(self.AUTHENTICATED, test, enrolled_device=enrolled_device)

    def set_completed_status(self, enrolled_device):
        if self.ota_enrollment.scep_verification:
            scep_ok = self.phase2_scep_request is not None and self.phase3_scep_request is not None
        else:
            scep_ok = True
        test = (enrolled_device
                and scep_ok
                and self.status == self.AUTHENTICATED
                and self.enrolled_device == enrolled_device)
        self._set_next_status(self.COMPLETED, test)


# DEP Enrollment


class DEPOrganization(models.Model):
    # org type
    EDU = "edu"
    ORG = "org"
    TYPE_CHOICES = (
        (EDU, EDU),
        (ORG, ORG)
    )
    # org version
    V1 = "v1"
    V2 = "v2"
    VERSION_CHOICES = (
        (V1, "ADP"),
        (V2, "ASM"),
    )
    identifier = models.CharField(max_length=128)
    admin_id = models.EmailField()
    name = models.TextField()
    email = models.EmailField()
    phone = models.TextField()
    address = models.TextField()
    type = models.CharField(max_length=3, choices=TYPE_CHOICES)
    version = models.CharField(max_length=2, choices=VERSION_CHOICES)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def address_lines(self):
        return "\n".join(line for line in (line.strip() for line in self.address.split(",")) if line)


class DEPToken(models.Model):
    certificate = models.BinaryField(editable=False)
    private_key = models.TextField(null=True, editable=False)

    consumer_key = models.CharField(max_length=128, null=True, editable=False)
    consumer_secret = models.TextField(null=True, editable=False)
    access_token = models.CharField(max_length=128, null=True, editable=False)
    access_secret = models.TextField(null=True, editable=False)
    access_token_expiry = models.DateTimeField(null=True, editable=False)

    sync_cursor = models.CharField(max_length=128, null=True, editable=False)
    last_synced_at = models.DateTimeField(null=True, editable=False)

    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return "DEP token {}".format(self.pk)

    def get_absolute_url(self):
        return reverse("mdm:dep_token", args=(self.pk,))

    def has_expired(self):
        return self.access_token_expiry and self.access_token_expiry <= timezone.now()

    def expires_soon(self):
        # TODO: hard coded 7 days
        return self.access_token_expiry and self.access_token_expiry <= timezone.now() + datetime.timedelta(days=7)

    # secret

    def _get_secret_engine_kwargs(self, field):
        if not self.pk:
            raise ValueError("DEPToken must have a pk")
        return {"pk": self.pk, "model": "mdm.deptoken", "field": field}

    def get_private_key(self):
        if self.private_key:
            return decrypt(self.private_key, **self._get_secret_engine_kwargs("private_key"))

    def set_private_key(self, private_key):
        self.private_key = encrypt(private_key, **self._get_secret_engine_kwargs("private_key"))

    def get_consumer_secret(self):
        if self.consumer_secret:
            return decrypt_str(self.consumer_secret, **self._get_secret_engine_kwargs("consumer_secret"))

    def set_consumer_secret(self, consumer_secret):
        self.consumer_secret = encrypt_str(consumer_secret, **self._get_secret_engine_kwargs("consumer_secret"))

    def get_access_secret(self):
        if self.access_secret:
            return decrypt_str(self.access_secret, **self._get_secret_engine_kwargs("access_secret"))

    def set_access_secret(self, access_secret):
        self.access_secret = encrypt_str(access_secret, **self._get_secret_engine_kwargs("access_secret"))

    def rewrap_secrets(self):
        if self.private_key:
            self.private_key = rewrap(self.private_key, **self._get_secret_engine_kwargs("private_key"))
        if self.consumer_secret:
            self.consumer_secret = rewrap(self.consumer_secret, **self._get_secret_engine_kwargs("consumer_secret"))
        if self.access_secret:
            self.access_secret = rewrap(self.access_secret, **self._get_secret_engine_kwargs("access_secret"))


class DEPVirtualServer(models.Model):
    name = models.TextField(editable=False)
    uuid = models.UUIDField(unique=True, editable=False)

    organization = models.ForeignKey(DEPOrganization, on_delete=models.PROTECT, editable=False)
    token = models.OneToOneField(DEPToken, on_delete=models.SET_NULL,
                                 editable=False, null=True, related_name="virtual_server")

    default_enrollment = models.ForeignKey("mdm.DEPEnrollment", on_delete=models.SET_NULL, null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("mdm:dep_virtual_server", args=(self.pk,))


class DEPEnrollment(MDMEnrollment):

    class UsernamePattern(models.TextChoices):
        DEVICE_USERNAME = "$REALM_USER.DEVICE_USERNAME", "Username prefix without '.'"
        EMAIL_PREFIX = "$REALM_USER.EMAIL_PREFIX", "Email prefix"

    # link with the Apple DEP web services
    uuid = models.UUIDField(unique=True, editable=False)
    virtual_server = models.ForeignKey(DEPVirtualServer, on_delete=models.CASCADE)

    # to protect the dep enrollment endpoint. Link to the meta business unit too
    enrollment_secret = models.OneToOneField(EnrollmentSecret, on_delete=models.CASCADE,
                                             related_name="dep_enrollment", editable=False)

    # Authentication

    # if linked to a realm, a user has to authenticate to get the mdm payload.
    # if realm, use the realm user either to auto populate the user form
    # or auto create the admin
    use_realm_user = models.BooleanField(
        default=False,
        help_text="Use this option to prefill the account creation info with the realm user attributes."
    )
    # if the realm user is used, the following attribute determines how the
    # the account username is derived from the realm user attributes.
    # see zentral.contrib.mdm.payloads.substitute_variables
    username_pattern = models.CharField(
        max_length=255, choices=UsernamePattern.choices,
        blank=True,
        help_text="The pattern used to derive the account username from the realm user attributes."
    )
    # if the realm user is not an admin, we will only use the info
    # to autopopulate the user form, and we will need a default admin
    realm_user_is_admin = models.BooleanField(
        default=True,
        help_text="If false, the user created from the realm user during the Setup Assistant will be "
                  "a regular user, and the admin account information is required."
    )
    # optional admin account info
    admin_full_name = models.CharField(max_length=80, blank=True, null=True)
    admin_short_name = models.CharField(max_length=32, blank=True, null=True)
    admin_password_hash = models.JSONField(null=True, editable=False)

    # standard DEP profile configuration

    # https://developer.apple.com/documentation/devicemanagement/profile
    name = models.CharField(max_length=125, unique=True)  # see CONFIG_NAME_INVALID error
    allow_pairing = models.BooleanField(default=False)  # deprecated in iOS 13
    auto_advance_setup = models.BooleanField(default=False)
    await_device_configured = models.BooleanField(default=False)
    # configuration_web_url is automatically set for authentication or direct MDM payload download
    department = models.CharField(max_length=125, blank=True)  # see DEPARTMENT_INVALID error
    # devices see DEPDevice
    is_mandatory = models.BooleanField(default=True)
    is_mdm_removable = models.BooleanField(default=False)  # can be set to False only if is_supervised is True
    is_multi_user = models.BooleanField(default=True)
    is_supervised = models.BooleanField(default=True)  # deprecated
    language = models.CharField(max_length=3, choices=ISO_639_1_CHOICES, blank=True)
    org_magic = models.CharField(max_length=256, blank=True)  # see MAGIC_INVALID error
    region = models.CharField(max_length=2, choices=ISO_3166_1_ALPHA_2_CHOICES, blank=True)
    skip_setup_items = ArrayField(models.CharField(max_length=64), editable=False)
    # TODO: supervising_host_certs
    support_email_address = models.EmailField(max_length=250, blank=True)  # see SUPPORT_EMAIL_INVALID error
    support_phone_number = models.CharField(max_length=50, blank=True)  # see SUPPORT_PHONE_INVALID error
    # url is automatically set using the enrollment secret
    # Auto populate anchor_certs using the fullchain when building the profile payload?
    include_tls_certificates = models.BooleanField(default=False)

    # To require a software update before the enrollment
    ios_max_version = models.CharField(verbose_name="max. required iOS version", max_length=32, blank=True)
    ios_min_version = models.CharField(verbose_name="min. required iOS version", max_length=32, blank=True)
    macos_max_version = models.CharField(verbose_name="max. required macOS version", max_length=32, blank=True)
    macos_min_version = models.CharField(verbose_name="min. required macOS version", max_length=32, blank=True)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("mdm:dep_enrollment", args=(self.pk,))

    def assigned_devices(self):
        return self.depdevice_set.exclude(last_op_type=DEPDevice.OP_TYPE_DELETED)

    def serialize_for_event(self, keys_only=False):
        d = {
            "pk": self.pk,
            "uuid": str(self.uuid),
            "name": self.name,
        }
        if keys_only:
            return d
        d.update({
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        })
        return d

    def has_hardcoded_admin(self):
        return self.admin_full_name and self.admin_short_name and self.admin_password_hash

    def requires_account_configuration(self):
        return self.use_realm_user or self.has_hardcoded_admin()

    def can_be_deleted(self):
        return self.depenrollmentsession_set.count() == 0 and self.reenrollmentsession_set.count() == 0


class DEPDevice(models.Model):
    PROFILE_STATUS_EMPTY = "empty"
    PROFILE_STATUS_ASSIGNED = "assigned"
    PROFILE_STATUS_PUSHED = "pushed"
    PROFILE_STATUS_REMOVED = "removed"
    PROFILE_STATUS_CHOICES = (
        (PROFILE_STATUS_EMPTY, "Empty"),
        (PROFILE_STATUS_ASSIGNED, "Assigned"),
        (PROFILE_STATUS_PUSHED, "Pushed"),
        (PROFILE_STATUS_REMOVED, "Removed"),
    )

    OP_TYPE_ADDED = "added"
    OP_TYPE_MODIFIED = "modified"
    OP_TYPE_DELETED = "deleted"
    OP_TYPE_CHOICES = (
        (OP_TYPE_ADDED, "Added"),
        (OP_TYPE_MODIFIED, "Modified"),
        (OP_TYPE_DELETED, "Deleted"),
    )

    # link with the Apple DEP web services
    virtual_server = models.ForeignKey(DEPVirtualServer, on_delete=models.CASCADE, editable=False)
    serial_number = models.TextField(unique=True)

    # ABM info
    # device
    asset_tag = models.TextField(default="")
    color = models.CharField(max_length=256, default="")
    description = models.CharField(max_length=256, default="")
    device_family = models.CharField(max_length=256, default="")
    model = models.CharField(max_length=256, default="")
    os = models.CharField(max_length=256, default="")
    # assignment
    device_assigned_by = models.EmailField(editable=False)
    device_assigned_date = models.DateTimeField(editable=False)
    # sync service
    last_op_type = models.CharField(max_length=64, choices=OP_TYPE_CHOICES, null=True, editable=False)
    last_op_date = models.DateTimeField(null=True, editable=False)
    # profile
    profile_status = models.CharField(max_length=64,
                                      choices=PROFILE_STATUS_CHOICES,
                                      default=PROFILE_STATUS_EMPTY,
                                      editable=False)
    profile_uuid = models.UUIDField(null=True, editable=False)
    profile_assign_time = models.DateTimeField(null=True, editable=False)
    profile_push_time = models.DateTimeField(null=True, editable=False)

    # Zentral enrollment/profile
    enrollment = models.ForeignKey(DEPEnrollment, on_delete=models.PROTECT, null=True)

    disowned_at = models.DateTimeField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("serial_number",)
        permissions = [
            ("disown_depdevice", "Can disown a DEP device"),
        ]

    def __str__(self):
        return self.serial_number

    def is_deleted(self):
        return self.last_op_type == self.OP_TYPE_DELETED

    def get_absolute_url(self):
        return reverse("mdm:dep_device", args=(self.pk,))

    def get_urlsafe_serial_number(self):
        return MetaMachine(self.serial_number).get_urlsafe_serial_number()


class DEPEnrollmentSessionManager(models.Manager):
    def create_from_dep_enrollment(self, dep_enrollment, serial_number, udid, commit=True):
        # Build a new secret, only for one enrollment, only for this machine
        # scep server.

        enrollment_secret = dep_enrollment.enrollment_secret

        meta_business_unit = enrollment_secret.meta_business_unit
        tags = list(enrollment_secret.tags.all())

        # verified only once with the SCEP payload
        quota = 1

        new_es = EnrollmentSecret(
            meta_business_unit=meta_business_unit,
            serial_numbers=[serial_number],
            udids=[udid],
            quota=quota,
        )
        new_es.save(secret_length=56)  # CN max 64 - $ separator - prefix MDM$DEP
        new_es.tags.set(tags)
        enrollment_session = self.model(status=self.model.STARTED,
                                        dep_enrollment=dep_enrollment,
                                        enrollment_secret=new_es)
        if commit:
            enrollment_session.save()
        return enrollment_session


class DEPEnrollmentSession(EnrollmentSession):
    STARTED = "STARTED"
    SCEP_VERIFIED = "SCEP_VERIFIED"
    AUTHENTICATED = "AUTHENTICATED"
    COMPLETED = "COMPLETED"
    STATUS_CHOICES = (
        (STARTED, _("Started")),
        (SCEP_VERIFIED, _("SCEP verified")),
        (AUTHENTICATED, _("Authenticated")),  # first MDM Checkin Authenticate call
        (COMPLETED, _("Completed")),  # first MDM Checkin TokenUpdate call
    )
    status = models.CharField(max_length=64, choices=STATUS_CHOICES)
    dep_enrollment = models.ForeignKey(DEPEnrollment, on_delete=models.CASCADE)
    enrollment_secret = models.OneToOneField(EnrollmentSecret, on_delete=models.PROTECT,
                                             related_name="dep_enrollment_session")
    scep_request = models.ForeignKey(EnrollmentSecretRequest, on_delete=models.PROTECT, null=True, related_name="+")

    objects = DEPEnrollmentSessionManager()

    def get_enrollment(self):
        return self.dep_enrollment

    def get_prefix(self):
        if self.status == self.STARTED:
            return "MDM$DEP"
        else:
            raise ValueError("Wrong enrollment sessions status")

    def serialize_for_event(self):
        return super().serialize_for_event("dep", {"dep_enrollment": self.dep_enrollment.serialize_for_event()})

    def get_blueprint(self):
        return self.dep_enrollment.blueprint

    # status update methods

    def set_scep_verified_status(self, es_request):
        test = (es_request
                and self.status == self.STARTED
                and self.scep_request is None
                and not self.enrolled_device)
        self._set_next_status(self.SCEP_VERIFIED, test, scep_request=es_request)

    def set_authenticated_status(self, enrolled_device):
        if self.dep_enrollment.scep_verification:
            allowed_statuses = (self.SCEP_VERIFIED,)
            scep_ok = self.scep_request is not None
        else:
            allowed_statuses = (self.STARTED, self.SCEP_VERIFIED)
            scep_ok = True
        test = (enrolled_device
                and scep_ok
                and self.status in allowed_statuses
                and not self.enrolled_device)
        self._set_next_status(self.AUTHENTICATED, test, enrolled_device=enrolled_device)

    def set_completed_status(self, enrolled_device):
        if self.dep_enrollment.scep_verification:
            scep_ok = self.scep_request is not None
        else:
            scep_ok = True
        test = (enrolled_device
                and scep_ok
                and self.status == self.AUTHENTICATED
                and self.enrolled_device == enrolled_device)
        self._set_next_status(self.COMPLETED, test)


class DEPEnrollmentCustomView(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    dep_enrollment = models.ForeignKey(DEPEnrollment, on_delete=models.CASCADE)
    custom_view = models.ForeignKey(EnrollmentCustomView, on_delete=models.CASCADE)
    weight = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (
            ("dep_enrollment", "custom_view"),
            ("dep_enrollment", "weight"),
        )

    def __str__(self):
        return self.custom_view.name

    def get_absolute_url(self):
        return reverse("mdm:dep_enrollment", args=(self.dep_enrollment.pk,)) + f"#cv-{self.pk}"

    def serialize_for_event(self):
        return {
            "pk": str(self.pk),
            "dep_enrollment": self.dep_enrollment.serialize_for_event(keys_only=True),
            "custom_view": self.custom_view.serialize_for_event(keys_only=True),
            "weight": self.weight,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


# User Enrollment


class UserEnrollment(MDMEnrollment):
    name = models.CharField(max_length=256, unique=True)

    enrollment_secret = models.OneToOneField(EnrollmentSecret, on_delete=models.CASCADE,
                                             related_name="user_enrollment")
    # Realm is required, but not in the database schema.
    # User enrollments via profiles, with authentication in the device is deprecated
    # and has been removed.

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return self.name

    def serialize_for_event(self):
        d = {"pk": self.pk,
             "name": self.name,
             "created_at": self.created_at,
             "updated_at": self.updated_at}
        d.update(self.enrollment_secret.serialize_for_event())
        return d

    def get_absolute_url(self):
        return reverse("mdm:user_enrollment", args=(self.pk,))

    def get_service_discovery_full_url(self):
        if self.realm:
            return "https://{}{}".format(
                settings["api"]["fqdn"],
                reverse("mdm_public:user_enrollment_service_discovery", args=(self.enrollment_secret.secret,))
            )

    def revoke(self):
        if not self.enrollment_secret.revoked_at:
            # TODO events
            self.enrollment_secret.revoked_at = timezone.now()
            self.enrollment_secret.save()
            self.save()

    def can_be_deleted(self):
        return self.userenrollmentsession_set.count() == 0 and self.reenrollmentsession_set.count() == 0


class UserEnrollmentSessionManager(models.Manager):
    def create_from_user_enrollment(self, user_enrollment):
        enrollment_secret = user_enrollment.enrollment_secret
        tags = list(enrollment_secret.tags.all())
        new_es = EnrollmentSecret(
            meta_business_unit=enrollment_secret.meta_business_unit,
            quota=10,  # verified at the beginning of the authentication and once with SCEP
            expired_at=enrollment_secret.expired_at
        )
        new_es.save(secret_length=55)  # CN max 64 - $ separator - mdm$user
        new_es.tags.set(tags)
        enrollment_session = self.model(status=self.model.ACCOUNT_DRIVEN_START,
                                        user_enrollment=user_enrollment,
                                        enrollment_secret=new_es)
        enrollment_session.save()
        return enrollment_session


class UserEnrollmentSession(EnrollmentSession):
    ACCOUNT_DRIVEN_START = "ACCOUNT_DRIVEN_START"
    ACCOUNT_DRIVEN_AUTHENTICATED = "ACCOUNT_DRIVEN_AUTHENTICATED"
    STARTED = "STARTED"
    SCEP_VERIFIED = "SCEP_VERIFIED"
    AUTHENTICATED = "AUTHENTICATED"
    COMPLETED = "COMPLETED"
    STATUS_CHOICES = (
        (ACCOUNT_DRIVEN_START, _("Account-based onboarding initiated")),
        (ACCOUNT_DRIVEN_AUTHENTICATED, _("Account-based onboarding authenticated")),
        (STARTED, _("Started")),
        (SCEP_VERIFIED, _("SCEP verified")),
        (AUTHENTICATED, _("Authenticated")),  # first MDM Checkin Authenticate call
        (COMPLETED, _("Completed")),  # first MDM Checkin TokenUpdate call
    )
    status = models.CharField(max_length=64, choices=STATUS_CHOICES)
    user_enrollment = models.ForeignKey(UserEnrollment, on_delete=models.CASCADE)
    enrollment_secret = models.OneToOneField(EnrollmentSecret, on_delete=models.PROTECT,
                                             related_name="user_enrollment_session")
    scep_request = models.ForeignKey(EnrollmentSecretRequest, on_delete=models.PROTECT, null=True, related_name="+")

    managed_apple_id = models.EmailField(null=True)
    access_token = models.CharField(max_length=40, unique=True, null=True)

    objects = UserEnrollmentSessionManager()

    def get_enrollment(self):
        return self.user_enrollment

    def get_prefix(self):
        if self.status == self.STARTED:
            return "MDM$USER"
        else:
            raise ValueError("Wrong enrollment sessions status")

    def serialize_for_event(self):
        return super().serialize_for_event("user", {"user_enrollment": self.user_enrollment.serialize_for_event()})

    def get_blueprint(self):
        return self.user_enrollment.blueprint

    # status update methods

    def set_account_driven_authenticated_status(self, realm_user):
        test = (realm_user
                and realm_user.email
                and self.status == self.ACCOUNT_DRIVEN_START)
        self._set_next_status(self.ACCOUNT_DRIVEN_AUTHENTICATED, test,
                              realm_user=realm_user,
                              managed_apple_id=realm_user.email,
                              access_token=get_random_string(40))

    def set_started_status(self):
        test = (self.realm_user
                and self.managed_apple_id
                and self.access_token
                and self.status == self.ACCOUNT_DRIVEN_AUTHENTICATED)
        self._set_next_status(self.STARTED, test)

    def set_scep_verified_status(self, es_request):
        test = (es_request
                and self.status == self.STARTED
                and self.scep_request is None
                and not self.enrolled_device)
        self._set_next_status(self.SCEP_VERIFIED, test, scep_request=es_request)

    def set_authenticated_status(self, enrolled_device):
        if self.user_enrollment.scep_verification:
            allowed_statuses = (self.SCEP_VERIFIED,)
            scep_ok = self.scep_request is not None
        else:
            allowed_statuses = (self.STARTED, self.SCEP_VERIFIED)
            scep_ok = True
        test = (enrolled_device
                and scep_ok
                and self.status in allowed_statuses
                and not self.enrolled_device)
        self._set_next_status(self.AUTHENTICATED, test, enrolled_device=enrolled_device)

    def set_completed_status(self, enrolled_device):
        if self.user_enrollment.scep_verification:
            scep_ok = self.scep_request is not None
        else:
            scep_ok = True
        test = (enrolled_device
                and scep_ok
                and self.status == self.AUTHENTICATED
                and self.enrolled_device == enrolled_device)
        self._set_next_status(self.COMPLETED, test)


# MDM re-enrollment


class ReEnrollmentSessionManager(models.Manager):
    def create_from_enrollment_session(self, enrollment_session):
        if not enrollment_session.enrolled_device:
            raise ValueError("The enrollment session doesn't have an enrolled device")
        enrollment = enrollment_session.get_enrollment()
        enrollment_secret = enrollment.enrollment_secret

        meta_business_unit = enrollment_secret.meta_business_unit
        tags = list(enrollment_secret.tags.all())

        # verified only once with the SCEP payload
        quota = 1

        # expires 60 minutes from now, plenty enough for the device to contact the SCEP server
        expired_at = timezone.now() + datetime.timedelta(hours=1)

        enrolled_device = enrollment_session.enrolled_device
        new_es = EnrollmentSecret(
            meta_business_unit=meta_business_unit,
            serial_numbers=[enrolled_device.serial_number],
            udids=[enrolled_device.udid],
            quota=quota,
            expired_at=expired_at,
        )
        new_es.save(secret_length=57)  # CN max 64 - $ separator - prefix MDM$RE
        new_es.tags.set(tags)
        enrollment_session = self.model(
            status=self.model.STARTED,
            enrollment_secret=new_es,
            enrolled_device=enrolled_device,  # important, see _reenroll !!
            realm_user=enrollment_session.realm_user,
            first_enrolled_at=enrollment_session.device_enrolled_at,
        )
        if isinstance(enrollment, DEPEnrollment):
            enrollment_session.dep_enrollment = enrollment
        elif isinstance(enrollment, OTAEnrollment):
            enrollment_session.ota_enrollment = enrollment
        elif isinstance(enrollment, UserEnrollment):
            enrollment_session.user_enrollment = enrollment
        else:
            raise ValueError("Unknown enrollment type")
        enrollment_session.save()
        return enrollment_session


class ReEnrollmentSession(EnrollmentSession):
    STARTED = "STARTED"
    SCEP_VERIFIED = "SCEP_VERIFIED"
    AUTHENTICATED = "AUTHENTICATED"
    COMPLETED = "COMPLETED"
    STATUS_CHOICES = (
        (STARTED, _("Started")),
        (SCEP_VERIFIED, _("SCEP verified")),  # Optional, the SCEP service verified the MDM CSR
        (AUTHENTICATED, _("Authenticated")),  # first MDM Checkin Authenticate call
        (COMPLETED, _("Completed")),  # first MDM Checkin TokenUpdate call
    )
    status = models.CharField(max_length=64, choices=STATUS_CHOICES)
    dep_enrollment = models.ForeignKey(DEPEnrollment, on_delete=models.CASCADE, null=True)
    ota_enrollment = models.ForeignKey(OTAEnrollment, on_delete=models.CASCADE, null=True)
    user_enrollment = models.ForeignKey(UserEnrollment, on_delete=models.CASCADE, null=True)
    enrollment_secret = models.OneToOneField(EnrollmentSecret, on_delete=models.PROTECT,
                                             related_name="reenrollment_session")
    scep_request = models.ForeignKey(EnrollmentSecretRequest, on_delete=models.PROTECT, null=True, related_name="+")
    first_enrolled_at = models.DateTimeField()

    objects = ReEnrollmentSessionManager()

    def get_enrollment(self):
        if self.dep_enrollment:
            return self.dep_enrollment
        elif self.ota_enrollment:
            return self.ota_enrollment
        else:
            return self.user_enrollment

    def get_prefix(self):
        if self.status == self.STARTED:
            return "MDM$RE"
        else:
            raise ValueError("Wrong enrollment sessions status")

    @property
    def device_enrolled_at(self):
        return self.first_enrolled_at

    def serialize_for_event(self):
        return super().serialize_for_event("re", self.get_enrollment().serialize_for_event())

    def get_blueprint(self):
        return self.get_enrollment().blueprint

    # status update methods

    def set_scep_verified_status(self, es_request):
        test = (es_request
                and self.status == self.STARTED
                and self.scep_request is None)
        self._set_next_status(self.SCEP_VERIFIED, test, scep_request=es_request)

    def set_authenticated_status(self, enrolled_device):
        if self.get_enrollment().scep_verification:
            allowed_statuses = (self.SCEP_VERIFIED,)
            scep_ok = self.scep_request is not None
        else:
            allowed_statuses = (self.STARTED, self.SCEP_VERIFIED)
            scep_ok = True
        test = (enrolled_device
                and scep_ok
                and self.status in allowed_statuses
                and self.enrolled_device == enrolled_device)
        self._set_next_status(self.AUTHENTICATED, test, enrolled_device=enrolled_device)

    def set_completed_status(self, enrolled_device):
        if self.get_enrollment().scep_verification:
            scep_ok = self.scep_request is not None
        else:
            scep_ok = True
        test = (enrolled_device
                and scep_ok
                and self.status == self.AUTHENTICATED
                and self.enrolled_device == enrolled_device)
        self._set_next_status(self.COMPLETED, test)


# Artifacts


class ArtifactManager(models.Manager):
    def can_be_deleted(self):
        return self.annotate(
            bpa_count=Count("blueprintartifact"),
            da_count=Count("artifactversion__deviceartifact"),
            ua_count=Count("artifactversion__userartifact"),
            dc_count=Count("artifactversion__devicecommand"),
            uc_count=Count("artifactversion__usercommand"),
            ref_count=Count("declarationref"),
        ).filter(
            bpa_count=0,
            da_count=0,
            ua_count=0,
            dc_count=0,
            uc_count=0,
            ref_count=0,
        )


class Artifact(models.Model):

    class Operation(models.TextChoices):
        INSTALLATION = "Installation"
        REMOVAL = "Removal"

    class Type(models.TextChoices):
        ACTIVATION = "Activation"
        ASSET = "Asset"
        CONFIGURATION = "Configuration"
        DATA_ASSET = "Data Asset"
        ENTERPRISE_APP = "Enterprise App"
        MANUAL_CONFIGURATION = "Configuration (manual)"
        PROFILE = "Profile"
        STORE_APP = "Store App"

        @property
        def is_activation(self):
            return self.value == self.ACTIVATION

        @property
        def is_asset(self):
            return self.value in (self.ASSET, self.DATA_ASSET)

        @property
        def is_configuration(self):
            return self.value in (self.CONFIGURATION, self.MANUAL_CONFIGURATION, self.PROFILE)

        @property
        def is_declaration(self):
            return self.is_configuration or self.is_asset or self.is_activation

        @property
        def is_ddm_only(self):
            return not self.value == self.PROFILE and self.is_declaration

        @property
        def is_raw_declaration(self):
            return self.value in (self.ACTIVATION, self.ASSET, self.CONFIGURATION, self.MANUAL_CONFIGURATION)

        @property
        def can_be_linked_to_blueprint(self):
            return not self.is_asset and not self.value == self.MANUAL_CONFIGURATION

        @property
        def can_be_installed(self):
            return self.value in (self.ENTERPRISE_APP, self.PROFILE, self.STORE_APP)

        @property
        def can_be_removed(self):
            return self.value in (self.PROFILE, self.STORE_APP)

    class ReinstallOnOSUpdate(models.TextChoices):
        NO = "No"
        MAJOR = "Major"
        MINOR = "Minor"
        PATCH = "Patch"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=256, unique=True)
    type = models.CharField(max_length=64, choices=Type.choices)
    # targets
    channel = models.CharField(max_length=64, choices=Channel.choices)
    platforms = ArrayField(models.CharField(max_length=64, choices=Platform.choices), default=get_platform_values)
    # when to install or reinstall
    requires = models.ManyToManyField("mdm.Artifact", related_name="requiredby_set", blank=True)
    install_during_setup_assistant = models.BooleanField(default=False)
    auto_update = models.BooleanField(default=True)
    reinstall_interval = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(366)],
        default=0,
        help_text="In days, the time interval after which the artifact will be reinstalled. "
                  "If 0, the artifact will not be reinstalled. Defaults to 0."
    )
    reinstall_on_os_update = models.CharField(
        max_length=5,
        choices=ReinstallOnOSUpdate.choices,
        default=ReinstallOnOSUpdate.NO,
    )

    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    objects = ArtifactManager()

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("mdm:artifact", args=(self.pk,))

    def get_type(self):
        return self.Type(self.type)

    def get_platforms(self):
        return [Platform(p) for p in self.platforms]

    def get_channel(self):
        return Channel(self.channel)

    @property
    def can_be_removed(self):
        return self.get_type().can_be_removed

    def blueprints(self):
        # directly included
        yield from Blueprint.objects.filter(
            blueprintartifact__artifact=self
        )
        # referenced by a declaration
        yield from Blueprint.objects.distinct().filter(
            blueprintartifact__artifact__artifactversion__declaration__declarationref__artifact=self
        )

    def can_be_deleted(self):
        return Artifact.objects.can_be_deleted().filter(pk=self.pk).count() == 1

    def serialize_for_event(self, keys_only=False):
        d = {"pk": str(self.pk), "name": self.name}
        if keys_only:
            return d
        d.update({
            "type": self.type,
            "channel": self.channel,
            "platforms": self.platforms,
            "requires": [a.serialize_for_event(keys_only=True) for a in self.requires.all().order_by("pk")],
            "install_during_setup_assistant": self.install_during_setup_assistant,
            "auto_update": self.auto_update,
            "reinstall_interval": self.reinstall_interval,
            "reinstall_on_os_update": self.reinstall_on_os_update,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        })
        return d


class FilteredBlueprintItem(models.Model):
    # platforms
    ios = models.BooleanField(default=False)
    ios_min_version = models.CharField(max_length=32, blank=True)
    ios_max_version = models.CharField(max_length=32, blank=True)
    ipados = models.BooleanField(default=False)
    ipados_min_version = models.CharField(max_length=32, blank=True)
    ipados_max_version = models.CharField(max_length=32, blank=True)
    macos = models.BooleanField(default=False)
    macos_min_version = models.CharField(max_length=32, blank=True)
    macos_max_version = models.CharField(max_length=32, blank=True)
    tvos = models.BooleanField(default=False)
    tvos_min_version = models.CharField(max_length=32, blank=True)
    tvos_max_version = models.CharField(max_length=32, blank=True)
    # shards
    shard_modulo = models.IntegerField(
        validators=[MinValueValidator(2), MaxValueValidator(100)],
        default=100,
    )
    default_shard = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        default=100,
    )
    excluded_tags = models.ManyToManyField(Tag, related_name="+", blank=True)

    class Meta:
        abstract = True

    @cached_property
    def tag_shards(self):
        fbpit_qs = (
            self.item_tags
            .select_related("tag__meta_business_unit", "tag__taxonomy")
            .all()
        )
        return [{"tag": fbpit.tag, "shard": fbpit.shard} for fbpit in fbpit_qs]

    @property
    def platforms(self):
        platforms = {}
        for platform in Platform:
            fieldname = platform.value.lower()
            if getattr(self, fieldname):
                platform_d = platforms.setdefault(platform, {})
                min_version = getattr(self, f"{fieldname}_min_version")
                if min_version:
                    platform_d["min"] = min_version
                max_version = getattr(self, f"{fieldname}_max_version")
                if max_version:
                    platform_d["max"] = max_version
        return platforms

    def serialize_for_event(self):
        return {
            "ios": self.ios,
            "ios_min_version": self.ios_min_version,
            "ios_max_version": self.ios_max_version,
            "ipados": self.ipados,
            "ipados_min_version": self.ipados_min_version,
            "ipados_max_version": self.ipados_max_version,
            "macos": self.macos,
            "macos_min_version": self.macos_min_version,
            "macos_max_version": self.macos_max_version,
            "tvos": self.tvos,
            "tvos_min_version": self.tvos_min_version,
            "tvos_max_version": self.tvos_max_version,
            "shard_modulo": self.shard_modulo,
            "default_shard": self.default_shard,
            "excluded_tags": [tag.serialize_for_event(keys_only=True)
                              for tag in self.excluded_tags.all().order_by("pk")],
            "tag_shards": [item_tag.serialize_for_event()
                           for item_tag in self.item_tags.all().order_by("pk")]
        }


class FilteredBlueprintItemTag(models.Model):
    tag = models.ForeignKey(Tag, on_delete=models.CASCADE, related_name="+")
    shard = models.IntegerField(validators=[MinValueValidator(1), MaxValueValidator(100)], default=100)

    class Meta:
        abstract = True

    def serialize_for_event(self):
        return {
            "tag": self.tag.serialize_for_event(keys_only=True),
            "shard": self.shard,
        }


class BlueprintArtifact(FilteredBlueprintItem):
    blueprint = models.ForeignKey(Blueprint, on_delete=models.CASCADE)
    artifact = models.ForeignKey(Artifact, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    class Meta:
        unique_together = (("blueprint", "artifact"),)

    def get_absolute_url(self):
        return "{}#ba-{}".format(self.artifact.get_absolute_url(), self.pk)

    def serialize_for_event(self):
        d = super().serialize_for_event()
        d.update({
            "pk": self.pk,
            "blueprint": self.blueprint.serialize_for_event(keys_only=True),
            "artifact": self.artifact.serialize_for_event(keys_only=True),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        })
        return d


class BlueprintArtifactTag(FilteredBlueprintItemTag):
    blueprint_artifact = models.ForeignKey(BlueprintArtifact, on_delete=models.CASCADE, related_name="item_tags")

    class Meta:
        unique_together = (("blueprint_artifact", "tag"),)


class ArtifactVersionManager(models.Manager):
    def can_be_deleted(self):
        return self.annotate(
            da_count=Count("deviceartifact"),
            ua_count=Count("userartifact"),
            dc_count=Count("devicecommand"),
            uc_count=Count("usercommand"),
        ).filter(
            da_count=0,
            ua_count=0,
            dc_count=0,
            uc_count=0,
        )


class ArtifactVersion(FilteredBlueprintItem):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    artifact = models.ForeignKey(Artifact, on_delete=models.CASCADE)
    version = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    objects = ArtifactVersionManager()

    def __str__(self):
        return f"{self.artifact} v{self.version}"

    def get_absolute_url(self):
        return reverse("mdm:artifact_version", args=(self.artifact.pk, self.pk))

    class Meta:
        unique_together = (("artifact", "version"),)
        ordering = ("-version",)

    def can_be_deleted(self):
        return ArtifactVersion.objects.can_be_deleted().filter(pk=self.pk).count() == 1

    def serialize_for_event(self):
        d = super().serialize_for_event()
        d.update({
            "pk": str(self.id),
            "artifact": self.artifact.serialize_for_event(keys_only=True),
            "version": self.version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        })
        return d


class ArtifactVersionTag(FilteredBlueprintItemTag):
    artifact_version = models.ForeignKey(ArtifactVersion, on_delete=models.CASCADE, related_name="item_tags")

    class Meta:
        unique_together = (("artifact_version", "tag"),)


class Declaration(models.Model):
    artifact_version = models.OneToOneField(ArtifactVersion, related_name="declaration", on_delete=models.CASCADE)
    type = models.TextField()
    identifier = models.TextField(db_index=True)
    server_token = models.TextField(unique=True)
    payload = models.JSONField()

    def __str__(self):
        return self.identifier

    def delete(self, *args, **kwargs):
        self.artifact_version.delete(*args, **kwargs)
        super().delete(*args, **kwargs)

    def get_export_filename(self):
        slug = slugify(self.artifact_version.artifact.name)
        return f"{slug}_{self.pk}_v{self.artifact_version.version}.json"

    def get_full_dict(self):
        return {
            "Type": self.type,
            "Identifier": self.identifier,
            "ServerToken": self.server_token,
            "Payload": self.payload
        }

    def serialize_for_event(self):
        d = self.artifact_version.serialize_for_event()
        d["source"] = self.get_full_dict()
        return d


class DeclarationRef(models.Model):
    declaration = models.ForeignKey(Declaration, on_delete=models.CASCADE)
    key = ArrayField(models.CharField(max_length=256, validators=[MinLengthValidator(1)]))
    artifact = models.ForeignKey(Artifact, on_delete=models.CASCADE)

    class Meta:
        unique_together = (("declaration", "key"),)


def data_asset_path(instance, filename):
    _, ext = os.path.splitext(filename)
    return f"mdm/data_assets/{instance.artifact_version.artifact.pk}/{instance.artifact_version.pk}{ext}"


# We override the default mimetype for the ".plist" extension.
# Files can be stored in third party systems via django-storages. See:
# https://github.com/jschneier/django-storages/blob/b79ea310201e7afd659fe47e2882fe59aae5b517/storages/backends/gcloud.py#L41  # NOQA
# https://github.com/jschneier/django-storages/blob/b79ea310201e7afd659fe47e2882fe59aae5b517/storages/backends/s3.py#L630  # NOQA
# This way, we make sure the correct mimetype is stored in the object metadata, and used in the Http response headers.
PLIST_MIME_TYPE = "text/xml"
mimetypes.add_type(PLIST_MIME_TYPE, ".plist")


class DataAsset(models.Model):
    class Type(models.TextChoices):
        PLIST = "PLIST", _("PLIST (.plist)")
        ZIP = "ZIP", _("ZIP archive (.zip)")

    artifact_version = models.OneToOneField(ArtifactVersion, related_name="data_asset", on_delete=models.CASCADE)
    type = models.CharField(max_length=256, choices=Type.choices)
    file = models.FileField(upload_to=data_asset_path, storage=select_dist_storage)
    filename = models.TextField()
    file_size = models.BigIntegerField(validators=[MinValueValidator(1)])
    file_sha256 = models.CharField(max_length=64)

    def __str__(self):
        return self.filename

    def serialize_for_event(self):
        d = self.artifact_version.serialize_for_event()
        d.update({
            "type": self.type,
            "filename": self.filename,
            "file_size": self.file_size,
            "file_sha256": self.file_sha256,
        })
        return d

    def delete(self, *args, **kwargs):
        self.artifact_version.delete(*args, **kwargs)
        super().delete(*args, **kwargs)

    def get_type(self):
        return self.Type(self.type)

    def get_content_type(self):
        data_type = self.get_type()
        if data_type == self.Type.PLIST:
            return PLIST_MIME_TYPE
        elif data_type == self.Type.ZIP:
            return "application/zip"
        logger.error("Unknown content type for type %s", data_type)

    def get_export_filename(self):
        slug = slugify(self.artifact_version.artifact.name)
        _, ext = os.path.splitext(self.filename)
        return f"{slug}_{self.pk}_v{self.artifact_version.version}{ext}"


class Profile(models.Model):
    artifact_version = models.OneToOneField(ArtifactVersion, related_name="profile", on_delete=models.CASCADE)
    source = models.BinaryField()
    filename = models.TextField()
    payload_identifier = models.TextField(db_index=True)
    payload_uuid = models.TextField()
    payload_display_name = models.TextField()
    payload_description = models.TextField()

    def __str__(self):
        return self.payload_display_name

    @cached_property
    def payloads(self):
        return [
            (payload.get("PayloadType"), payload.get("PayloadDisplayName"))
            for payload in plistlib.loads(self.source).get("PayloadContent", [])
        ]

    def get_payload_description(self):
        return plistlib.loads(self.source).get("PayloadDescription")

    def installed_payload_identifier(self):
        return get_payload_identifier("artifact", self.artifact_version.artifact.pk)

    def installed_payload_uuid(self):
        return str(self.artifact_version.pk).upper()

    def serialize_for_event(self):
        d = self.artifact_version.serialize_for_event()
        d.update({
            "source": hashlib.sha1(self.source).hexdigest(),
            "filename": self.filename,
            "payload_identifier": self.payload_identifier,
            "payload_uuid": self.payload_uuid,
            "payload_display_name": self.payload_display_name,
            "payload_description": self.payload_description,
        })
        return d

    def delete(self, *args, **kwargs):
        self.artifact_version.delete(*args, **kwargs)
        super().delete(*args, **kwargs)

    def get_export_filename(self):
        slug = slugify(self.artifact_version.artifact.name)
        return f"{slug}_{self.pk}_v{self.artifact_version.version}.mobileconfig"


def enterprise_application_package_path(instance, filename):
    return f"mdm/enterprise_apps/{instance.artifact_version.artifact.pk}/{instance.artifact_version.pk}.pkg"


class EnterpriseApp(models.Model):
    artifact_version = models.OneToOneField(ArtifactVersion, related_name="enterprise_app", on_delete=models.CASCADE)
    package = models.FileField(upload_to=enterprise_application_package_path, storage=select_dist_storage)
    package_uri = models.TextField(default="")
    package_sha256 = models.CharField(max_length=64)
    package_size = models.BigIntegerField()
    filename = models.TextField()
    product_id = models.TextField()
    product_version = models.TextField()
    bundles = models.JSONField(default=list)
    manifest = models.JSONField()
    ios_app = models.BooleanField(default=False)
    configuration = models.BinaryField(null=True)
    install_as_managed = models.BooleanField(default=False)
    remove_on_unenroll = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.product_id} {self.product_version}"

    class Meta:
        indexes = [models.Index(fields=["product_id", "product_version"])]

    def get_configuration(self):
        if self.configuration:
            return plistlib.loads(self.configuration)

    def get_configuration_plist(self):
        configuration = self.get_configuration()
        if configuration:
            return plistlib.dumps(configuration).decode("utf-8")

    def has_configuration(self):
        return self.configuration is not None

    def serialize_for_event(self):
        d = self.artifact_version.serialize_for_event()
        d.update({
            "package_sha256": self.package_sha256,
            "package_size": self.package_size,
            "filename": self.filename,
            "product_id": self.product_id,
            "product_version": self.product_version,
            "bundles": self.bundles,
            "manifest": self.manifest,
            "ios_app": self.ios_app,
            "install_as_managed": self.install_as_managed,
            "remove_on_unenroll": self.remove_on_unenroll,
        })
        if self.package_uri:
            d["package_uri"] = self.package_uri
        configuration_plist = self.get_configuration_plist()
        if configuration_plist:
            d["configuration"] = configuration_plist
        return d

    def delete(self, *args, **kwargs):
        self.artifact_version.delete(*args, **kwargs)
        super().delete(*args, **kwargs)


@receiver(post_delete, sender=EnterpriseApp)
def post_delete_enterprise_app(sender, instance, *args, **kwargs):
    """Delete package"""
    try:
        instance.package.delete(save=False)
    except Exception:
        logger.exception("Could not delete enteprise app package")


class StoreApp(models.Model):
    artifact_version = models.OneToOneField(ArtifactVersion, related_name="store_app", on_delete=models.CASCADE)
    location_asset = models.ForeignKey(LocationAsset, on_delete=models.CASCADE)

    # attributes
    # https://developer.apple.com/documentation/devicemanagement/installapplicationcommand/command/attributes
    associated_domains = ArrayField(models.CharField(max_length=256, validators=[MinLengthValidator(3)]),
                                    blank=True, default=list)
    associated_domains_enable_direct_downloads = models.BooleanField(default=False)
    removable = models.BooleanField(default=False)  # iOS >= 14, tvOS >= 14
    vpn_uuid = models.TextField(blank=True, null=True)
    content_filter_uuid = models.TextField(blank=True, null=True)
    dns_proxy_uuid = models.TextField(blank=True, null=True)

    configuration = models.BinaryField(null=True)
    remove_on_unenroll = models.BooleanField(default=True)
    prevent_backup = models.BooleanField(default=False)

    def get_management_flags(self):
        management_flags = 0
        if self.remove_on_unenroll:
            management_flags += 1
        if self.prevent_backup:
            management_flags += 4
        return management_flags

    def get_configuration(self):
        if self.configuration:
            return plistlib.loads(self.configuration)

    def get_configuration_plist(self):
        configuration = self.get_configuration()
        if configuration:
            return plistlib.dumps(configuration).decode("utf-8")

    def has_configuration(self):
        return self.configuration is not None

    def get_absolute_url(self):
        return self.artifact_version.get_absolute_url()


class EnrolledDeviceLocationAssetAssociation(models.Model):
    """Used for on-the-fly asset association."""
    enrolled_device = models.ForeignKey(EnrolledDevice, on_delete=models.CASCADE)
    location_asset = models.ForeignKey(LocationAsset, on_delete=models.CASCADE)

    created_at = models.DateTimeField(auto_now_add=True)
    attempts = models.IntegerField(default=0)
    last_attempted_at = models.DateTimeField(null=True)

    class Meta:
        unique_together = (("enrolled_device", "location_asset"),)


class TargetArtifact(models.Model):

    class Status(models.TextChoices):
        ACKNOWLEDGED = "Acknowledged"
        AWAITING_CONFIRMATION = "AwaitingConfirmation"
        INSTALLED = "Installed"
        UNINSTALLED = "Uninstalled"
        FAILED = "Failed"
        REMOVAL_FAILED = "RemovalFailed"
        FORCE_REINSTALL = "ForceReinstall"

        @property
        def present(self):
            return self.value in (self.ACKNOWLEDGED, self.INSTALLED)

    artifact_version = models.ForeignKey(ArtifactVersion, on_delete=models.PROTECT)
    status = models.CharField(
        max_length=64,
        choices=Status.choices,
        default=Status.ACKNOWLEDGED
    )
    extra_info = models.JSONField(default=dict)

    # for reinstall interval
    installed_at = models.DateTimeField(null=True)
    # for reinstall at OS update
    os_version_at_install_time = models.CharField(max_length=64, null=True)
    # to better identify reinstalls
    unique_install_identifier = models.CharField(max_length=256, default="")
    install_count = models.IntegerField(default=0)
    retry_count = models.IntegerField(default=0)
    max_retry_count = models.IntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class DeviceArtifact(TargetArtifact):
    enrolled_device = models.ForeignKey(EnrolledDevice, on_delete=models.CASCADE, related_name="target_artifacts")

    class Meta:
        unique_together = ("enrolled_device", "artifact_version")


class UserArtifact(TargetArtifact):
    enrolled_user = models.ForeignKey(EnrolledUser, on_delete=models.CASCADE, related_name="target_artifacts")

    class Meta:
        unique_together = ("enrolled_user", "artifact_version")


# Commands


class RequestStatus(models.TextChoices):
    ACKNOWLEDGED = "Acknowledged"
    COMMAND_FORMAT_ERROR = "CommandFormatError"
    ERROR = "Error"
    IDLE = "Idle"
    NOT_NOW = "NotNow"

    @property
    def is_error(self):
        return self in (RequestStatus.ERROR, RequestStatus.COMMAND_FORMAT_ERROR)


class Command(models.Model):

    class Status(models.TextChoices):
        ACKNOWLEDGED = "Acknowledged"
        COMMAND_FORMAT_ERROR = "CommandFormatError"
        ERROR = "Error"
        NOT_NOW = "NotNow"

    uuid = models.UUIDField(unique=True, editable=False)

    name = models.CharField(max_length=128)
    artifact_version = models.ForeignKey(ArtifactVersion, on_delete=models.PROTECT, null=True)
    artifact_operation = models.CharField(max_length=64, choices=Artifact.Operation.choices, null=True)
    kwargs = models.JSONField(default=dict)

    not_before = models.DateTimeField(null=True)
    time = models.DateTimeField(null=True)  # no time => queued
    result = models.BinaryField(null=True)  # to store the result of some commands
    result_time = models.DateTimeField(null=True)
    status = models.CharField(max_length=64, choices=Status.choices, null=True)
    error_chain = models.JSONField(null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return " - ".join(s for s in (self.name, str(self.uuid), self.status) if s)

    class Meta:
        abstract = True


class DeviceCommand(Command):
    enrolled_device = models.ForeignKey(EnrolledDevice, on_delete=models.CASCADE, related_name="commands")


class UserCommand(Command):
    enrolled_user = models.ForeignKey(EnrolledUser, on_delete=models.CASCADE, related_name="commands")


# Apple software lookup service


class SoftwareUpdate(models.Model):
    platform = models.CharField(max_length=64, choices=Platform.choices)
    major = models.PositiveIntegerField()
    minor = models.PositiveIntegerField()
    patch = models.PositiveIntegerField()
    extra = models.CharField(max_length=32, blank=True)
    build = models.CharField(max_length=32, blank=True)
    prerequisite_build = models.CharField(max_length=32, blank=True)
    public = models.BooleanField()
    availability = DateRangeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (
            ("platform", "major", "minor", "patch", "extra", "build", "prerequisite_build", "public", "availability"),
        )

    @property
    def comparable_os_version(self):
        return tuple(e for e in (self.major, self.minor, self.patch, self.extra) if e != "")

    def target_os_version(self):
        s = ".".join(
            str(i)
            for a, i in ((a, getattr(self, a)) for a in ("major", "minor", "patch"))
            if i or a != "patch"
        )
        if self.extra:
            s = f"{s} {self.extra}"
        return s

    def __str__(self):
        s = self.target_os_version()
        if self.build:
            s = f"{s} ({self.build})"
        return s

    def summary(self):
        return f"{self.platform} {self}"

    def serialize_for_event(self, keys_only=False):
        d = {"pk": self.pk, "summary": self.summary()}
        if keys_only:
            return d
        for attr in (
            "platform",
            "major",
            "minor",
            "patch",
            "extra",
            "build",
            "prerequisite_build",
            "public",
            "created_at",
            "updated_at"
        ):
            val = getattr(self, attr)
            if val != "" and val is not None:
                d[attr] = val
        if isinstance(self.availability, tuple):
            # Set during creation or update
            available_from, available_until = self.availability
        else:
            # DateRange object from the DB adaptor
            available_from = self.availability.lower
            available_until = self.availability.upper
        if available_from:
            d["available_from"] = available_from
        if available_until:
            d["available_until"] = available_until
        return d


class SoftwareUpdateDeviceID(models.Model):
    software_update = models.ForeignKey(SoftwareUpdate, on_delete=models.CASCADE)
    device_id = models.CharField(max_length=32, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = (("software_update", "device_id"),)

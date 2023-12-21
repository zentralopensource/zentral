import enum
from django.contrib.postgres.fields import ArrayField
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models
from django.db.models import F, Q
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from zentral.contrib.inventory.models import BaseEnrollment, Tag
from zentral.utils.os_version import make_comparable_os_version


# configuration


class PrincipalUserDetectionSource(enum.Enum):
    company_portal = "Company portal"
    google_chrome = "Google Chrome"
    logged_in_user = "Logged-in user"

    @classmethod
    def choices(cls):
        return tuple((i.name, i.value) for i in cls)

    @classmethod
    def accepted_sources(cls):
        return set(i.name for i in cls)


class Configuration(models.Model):
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True)
    inventory_apps_full_info_shard = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        default=100
    )
    principal_user_detection_sources = ArrayField(
        models.CharField(max_length=64, choices=PrincipalUserDetectionSource.choices()),
        blank=True,
        default=list,
    )
    principal_user_detection_domains = ArrayField(
        models.CharField(max_length=255),
        blank=True,
        default=list
    )
    collected_condition_keys = ArrayField(
        models.CharField(max_length=128),
        blank=True,
        default=list,
        help_text="List of Munki condition keys to collect as machine extra facts"
    )
    managed_installs_sync_interval_days = models.IntegerField(
        "Managed installs sync interval in days",
        validators=[MinValueValidator(1), MaxValueValidator(90)],
        default=7
    )
    script_checks_run_interval_seconds = models.IntegerField(
        "Script checks run interval in seconds",
        validators=[MinValueValidator(3600), MaxValueValidator(604800)],
        default=86400
    )
    auto_reinstall_incidents = models.BooleanField(
        "Auto reinstall incidents",
        default=False,
        help_text="Enable automatic package reinstall incidents"
    )
    auto_failed_install_incidents = models.BooleanField(
        "Auto failed install incidents",
        default=False,
        help_text="Enable automatic package failed install incidents"
    )

    version = models.PositiveIntegerField(editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("munki:configuration", args=(self.pk,))

    def save(self, *args, **kwargs):
        if not self.id:
            self.version = 0
        else:
            self.version = F("version") + 1
        super().save(*args, **kwargs)

    def serialize_for_event(self, keys_only=False):
        d = {"pk": self.pk, "name": self.name}
        if not keys_only:
            if not isinstance(self.version, int):
                # version was updated with a CombinedExpression
                # it needs to be fetched from the DB for the JSON serialization
                self.refresh_from_db()
            d.update({
                "description": self.description,
                "inventory_apps_full_info_shard": self.inventory_apps_full_info_shard,
                "principal_user_detection_sources": self.principal_user_detection_sources,
                "principal_user_detection_domains": self.principal_user_detection_domains,
                "collected_condition_keys": self.collected_condition_keys,
                "managed_installs_sync_interval_days": self.managed_installs_sync_interval_days,
                "script_checks_run_interval_seconds": self.script_checks_run_interval_seconds,
                "auto_reinstall_incidents": self.auto_reinstall_incidents,
                "auto_failed_install_incidents": self.auto_failed_install_incidents,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
                "version": self.version,
            })
        return d


# enrollment


class Enrollment(BaseEnrollment):
    configuration = models.ForeignKey(Configuration, on_delete=models.CASCADE)

    def get_absolute_url(self):
        return "{}#enrollment-{}".format(self.configuration.get_absolute_url(), self.pk)

    def get_description_for_distributor(self):
        return "Zentral pre/postflight"

    def serialize_for_event(self):
        enrollment_dict = super().serialize_for_event()
        enrollment_dict["configuration"] = self.configuration.serialize_for_event(keys_only=True)
        return enrollment_dict


class EnrolledMachine(models.Model):
    enrollment = models.ForeignKey(Enrollment, on_delete=models.CASCADE)
    serial_number = models.TextField(db_index=True)
    token = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)


# munki state


class MunkiState(models.Model):
    machine_serial_number = models.TextField(unique=True)
    munki_version = models.CharField(max_length=32, blank=True, null=True)
    user_agent = models.CharField(max_length=64)
    ip = models.GenericIPAddressField(blank=True, null=True)
    sha1sum = models.CharField(max_length=40, blank=True, null=True)
    last_managed_installs_sync = models.DateTimeField(blank=True, null=True)
    last_script_checks_run = models.DateTimeField(blank=True, null=True)
    run_type = models.CharField(max_length=64, blank=True, null=True)
    start_time = models.DateTimeField(blank=True, null=True)
    end_time = models.DateTimeField(blank=True, null=True)
    last_seen = models.DateTimeField(auto_now=True)


# managed install


class ManagedInstall(models.Model):
    machine_serial_number = models.TextField(db_index=True)
    name = models.TextField(db_index=True)
    display_name = models.TextField()
    installed_version = models.TextField(null=True)
    installed_at = models.DateTimeField(null=True)
    reinstall = models.BooleanField(default=False)
    failed_version = models.TextField(null=True)
    failed_at = models.DateTimeField(null=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (("machine_serial_number", "name"),)


# compliance check


class ScriptCheckManager(models.Manager):
    def iter_in_scope(self, comparable_os_version, arch_amd64, arch_arm64, tag_pks):
        qs = self.distinct().select_related("compliance_check")
        if arch_arm64:
            qs = qs.filter(arch_arm64=True)
        elif arch_amd64:
            qs = qs.filter(arch_amd64=True)
        tags_filter = Q(tags__isnull=True)
        if tag_pks:
            qs = qs.exclude(excluded_tags__pk__in=tag_pks)
            tags_filter |= Q(tags__pk__in=tag_pks)
        qs = qs.filter(tags_filter)
        for script_check in qs:
            if script_check.min_os_version:
                comparable_min_os_version = make_comparable_os_version(script_check.min_os_version)
                if comparable_os_version < comparable_min_os_version:
                    continue
            if script_check.max_os_version:
                comparable_max_os_version = make_comparable_os_version(script_check.max_os_version)
                if comparable_max_os_version > (0, 0, 0) and comparable_os_version >= comparable_max_os_version:
                    continue
            yield script_check


class ScriptCheck(models.Model):
    class Type(models.TextChoices):
        ZSH_STR = "ZSH_STR", _("ZSH script with string result")
        ZSH_INT = "ZSH_INT", _("ZSH script with integer result")
        ZSH_BOOL = "ZSH_BOOL", _("ZSH script with boolean result")

    compliance_check = models.OneToOneField(
        "compliance_checks.ComplianceCheck",
        on_delete=models.CASCADE,
        related_name="script_check",
        editable=False,
    )
    tags = models.ManyToManyField(Tag, blank=True, related_name="+")
    excluded_tags = models.ManyToManyField(Tag, blank=True, related_name="+")
    arch_amd64 = models.BooleanField(verbose_name="Run on Intel architecture", default=True)
    arch_arm64 = models.BooleanField(verbose_name="Run on Apple Silicon architecture", default=True)
    min_os_version = models.CharField(max_length=32, blank=True)
    max_os_version = models.CharField(max_length=32, blank=True)
    type = models.CharField(max_length=32, choices=Type.choices, default=Type.ZSH_STR)
    source = models.TextField()
    expected_result = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = ScriptCheckManager()

    def __str__(self):
        return self.compliance_check.name

    def get_absolute_url(self):
        return reverse("munki:script_check", args=(self.pk,))

    def serialize_for_event(self):
        d = {
            "pk": self.pk,
            "compliance_check": self.compliance_check.serialize_for_event(),
            "tags": [
                t.serialize_for_event(keys_only=True)
                for t in self.tags.select_related("taxonomy", "meta_business_unit").all().order_by("pk")
            ],
            "excluded_tags": [
                t.serialize_for_event(keys_only=True)
                for t in self.excluded_tags.select_related("taxonomy", "meta_business_unit").all().order_by("pk")
            ],
            "arch_amd64": self.arch_amd64,
            "arch_arm64": self.arch_arm64,
            "type": str(self.type),
            "source": self.source,
            "expected_result": self.expected_result,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
        if self.min_os_version:
            d["min_os_version"] = self.min_os_version
        if self.max_os_version:
            d["max_os_version"] = self.max_os_version
        return d

    def delete(self, *args, **kwargs):
        self.compliance_check.delete()
        return super().delete(*args, **kwargs)

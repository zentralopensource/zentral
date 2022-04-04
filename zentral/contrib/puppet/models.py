import hmac
import hashlib
import logging
from urllib.parse import urlparse
from django.contrib.postgres.fields import ArrayField
from django.core.cache import cache
from django.core.validators import MaxValueValidator, MinLengthValidator, MinValueValidator
from django.db import models
from django.db.models import F
from django.db.models.signals import post_delete, post_save
from django.urls import reverse
from django.utils.crypto import constant_time_compare
from zentral.conf import settings
from zentral.core.secret_engines import decrypt_str, encrypt_str, rewrap
from zentral.utils.certificates import iter_cert_trees


logger = logging.getLogger("zentral.contrib.puppet.models")


class Instance(models.Model):
    business_unit = models.ForeignKey("inventory.BusinessUnit", on_delete=models.PROTECT, related_name="+")
    # PuppetDB
    url = models.URLField("URL", unique=True, help_text="PuppetDB base URL")
    # PuppetDB authentication
    ca_chain = models.TextField("CA chain", help_text="Puppet CA chain (PEM). Used to verify the PuppetDB certificate")
    rbac_token = models.TextField(editable=False)  # secret
    cert = models.TextField(
        "Client certificate", blank=True,
        help_text="Client certificate (PEM) to authenticate with PuppetDB"
    )
    key = models.TextField(editable=False)  # secret
    timeout = models.IntegerField(
        "Requests timeout",
        validators=[MinValueValidator(1), MaxValueValidator(30)], default=10,
        help_text="Timeout in seconds (1→30) used for the PuppetDB requests"
    )
    # Facts
    group_fact_keys = ArrayField(
        models.CharField(max_length=256, validators=[MinLengthValidator(1)]),
        blank=True,
        default=list,
        help_text="Comma separated list of the group facts to collect"
    )
    extra_fact_keys = ArrayField(
        models.CharField(max_length=256, validators=[MinLengthValidator(1)]),
        blank=True,
        default=list,
        help_text="Comma separated list of the extra facts to collect"
    )
    puppetboard_url = models.URLField("PuppetBoard URL", blank=True)
    # Packages
    deb_packages_shard = models.IntegerField(
        "Debian packages shard",
        validators=[MinValueValidator(0), MaxValueValidator(100)], default=100,
        help_text="Restrict the collection of Debian packages to a percentage (0→100) of hosts"
    )
    programs_shard = models.IntegerField(
        "Windows programs shard",
        validators=[MinValueValidator(0), MaxValueValidator(100)], default=100,
        help_text="Restrict the collection of Windows programs to a percentage (0→100) of hosts"
    )
    # Report processor
    report_processor_token = models.TextField(editable=False)  # secret
    # Heartbeats
    report_heartbeat_timeout = models.IntegerField(
        validators=[MinValueValidator(600),
                    MaxValueValidator(172800)],
        default=3600,
        help_text="in seconds, 600 (10 min) → 172800 (2 days)"
    )
    # Versioning
    version = models.PositiveIntegerField(editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.hostname

    def get_absolute_url(self):
        return reverse("puppet:instance", args=(self.pk,))

    def get_post_report_full_url(self):
        return "https://{}{}".format(settings["api"]["fqdn"], reverse("puppet:post_report", args=(self.pk,)))

    def save(self, *args, **kwargs):
        if not self.pk:
            self.version = 0
        else:
            self.version = F("version") + 1
        super().save(*args, **kwargs)

    @property
    def hostname(self):
        return urlparse(self.url).netloc

    def observer_dict(self):
        return {"hostname": self.hostname,
                "vendor": "Puppet, Inc",
                "product": "Puppet",
                "type": "IT Automation",
                "content_type": "puppet.instance",
                "pk": self.pk}

    def serialize_for_event(self):
        return {"hostname": self.hostname,
                "pk": self.pk}

    # certificates info

    def iter_ca_chain_cert_trees(self):
        yield from iter_cert_trees(self.ca_chain)

    def get_cert_tree(self):
        for cert_tree in iter_cert_trees(self.cert):
            return cert_tree

    # secrets

    def get_rbac_token(self):
        if not self.pk:
            raise ValueError("Instance must have a PK")
        return decrypt_str(self.rbac_token, field="rbac_token", model="puppet.instance", pk=self.pk)

    def set_rbac_token(self, rbac_token):
        if not self.pk:
            raise ValueError("Instance must have a PK")
        self.rbac_token = encrypt_str(rbac_token, field="rbac_token", model="puppet.instance", pk=self.pk)

    def get_key(self):
        if not self.pk:
            raise ValueError("Instance must have a PK")
        return decrypt_str(self.key, field="key", model="puppet.instance", pk=self.pk)

    def set_key(self, key):
        if not self.pk:
            raise ValueError("Instance must have a PK")
        self.key = encrypt_str(key, field="key", model="puppet.instance", pk=self.pk)

    def get_report_processor_token(self):
        if not self.pk:
            raise ValueError("Instance must have a PK")
        return decrypt_str(
            self.report_processor_token, field="report_processor_token", model="puppet.instance", pk=self.pk
        )

    def set_report_processor_token(self, report_processor_token):
        if not self.pk:
            raise ValueError("Instance must have a PK")
        self.report_processor_token = encrypt_str(
            report_processor_token, field="report_processor_token", model="puppet.instance", pk=self.pk
        )

    def rewrap_secrets(self):
        if not self.pk:
            raise ValueError("Instance must have a PK")
        self.rbac_token = rewrap(self.rbac_token, field="rbac_token", model="puppet.instance", pk=self.pk)
        self.key = rewrap(self.key, field="key", model="puppet.instance", pk=self.pk)
        self.report_processor_token = rewrap(
            self.report_processor_token, field="report_processor_token", model="puppet.instance", pk=self.pk
        )


# instance cache for post report endpoint auth


def _get_cache_key(pk):
    return f"puppet.instance.{pk}.post-report-auth"


def _compute_token_digest(cache_key, token):
    return hmac.digest(cache_key.encode("utf-8"), token.encode("utf-8"), hashlib.sha256)


def update_cache(instance):
    cache_key = _get_cache_key(instance.pk)
    token_digest = _compute_token_digest(cache_key, instance.get_report_processor_token())
    version = instance.version
    observer_dict = instance.observer_dict()
    value = (token_digest, version, observer_dict)
    cache.set(cache_key, value)
    return value


def test_report_processor_token(pk, auth_token):
    cache_key = _get_cache_key(pk)
    try:
        token_digest, version, observer_dict = cache.get(cache_key)
    except TypeError:
        instance = Instance.objects.get(pk=pk)
        token_digest, version, observer_dict = update_cache(instance)
    if constant_time_compare(_compute_token_digest(cache_key, auth_token), token_digest):
        return version, observer_dict
    else:
        raise ValueError


def delete_from_cache(pk):
    cache.delete(_get_cache_key(pk))


# signals


def update_cache_signal_handler(sender, instance, **kwargs):
    if instance.report_processor_token:
        if not isinstance(instance.version, int):
            instance.refresh_from_db()
        update_cache(instance)


post_save.connect(update_cache_signal_handler, sender=Instance)


def delete_from_cache_signal_handler(sender, instance, **kwargs):
    delete_from_cache(instance.pk)


post_delete.connect(delete_from_cache_signal_handler, sender=Instance)

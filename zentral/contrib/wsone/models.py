import logging
from urllib.parse import urlparse
from django.contrib.postgres.fields import ArrayField
from django.core.validators import MinLengthValidator
from django.db import models
from django.db.models import F
from django.urls import reverse
from zentral.conf import settings
from zentral.core.secret_engines import decrypt_str, encrypt_str, rewrap


logger = logging.getLogger("zentral.contrib.wsone.models")


class Instance(models.Model):
    business_unit = models.ForeignKey("inventory.BusinessUnit", on_delete=models.PROTECT)
    # API
    server_url = models.URLField(unique=True)
    api_key = models.TextField()
    # OAuth 2.0
    client_id = models.TextField(help_text="OAuth 2.0 client ID")
    client_secret = models.TextField(help_text="OAuth 2.0 client secret")
    token_url = models.URLField()
    # Event notifications
    username = models.TextField(help_text="Event notifications username")
    password = models.TextField(help_text="Event notifications password")
    # Options
    excluded_groups = ArrayField(
        models.CharField(max_length=256, validators=[MinLengthValidator(1)]),
        blank=True,
        default=list,
        help_text=(
            "Comma separated list of the names of the organization groups to exclude. "
            "All children groups will be excluded as well."
        )
    )
    # Versioning
    version = models.PositiveIntegerField(editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.hostname

    def get_absolute_url(self):
        return reverse("wsone:instance", args=(self.pk,))

    def get_event_notifications_full_url(self):
        return "https://{}{}".format(settings["api"]["fqdn"], reverse("wsone:event_notifications", args=(self.pk,)))

    def save(self, *args, **kwargs):
        if not self.pk:
            self.version = 0
        elif kwargs.pop("bump_version", True):
            self.version = F("version") + 1
        super().save(*args, **kwargs)

    @property
    def hostname(self):
        return urlparse(self.server_url).netloc

    def observer_dict(self):
        return {"hostname": self.hostname,
                "vendor": "VMware",
                "product": "Workspace ONE",
                "type": "MDM",
                "content_type": "wsone.instance",
                "pk": self.pk}

    def serialize_for_event(self):
        return {"hostname": self.hostname,
                "pk": self.pk}

    # secrets

    def get_api_key(self):
        if not self.pk:
            raise ValueError("Instance must have a PK")
        return decrypt_str(self.api_key, field="api_key", model="wsone.instance", pk=self.pk)

    def set_api_key(self, api_key):
        if not self.pk:
            raise ValueError("Instance must have a PK")
        self.api_key = encrypt_str(api_key, field="api_key", model="wsone.instance", pk=self.pk)

    def get_client_secret(self):
        if not self.pk:
            raise ValueError("Instance must have a PK")
        return decrypt_str(self.client_secret, field="client_secret", model="wsone.instance", pk=self.pk)

    def set_client_secret(self, client_secret):
        if not self.pk:
            raise ValueError("Instance must have a PK")
        self.client_secret = encrypt_str(client_secret, field="client_secret", model="wsone.instance", pk=self.pk)

    def get_password(self):
        if not self.pk:
            raise ValueError("Instance must have a PK")
        return decrypt_str(self.password, field="password", model="wsone.instance", pk=self.pk)

    def set_password(self, password):
        if not self.pk:
            raise ValueError("Instance must have a PK")
        self.password = encrypt_str(password, field="password", model="wsone.instance", pk=self.pk)

    def rewrap_secrets(self):
        if not self.pk:
            raise ValueError("Instance must have a PK")
        self.api_key = rewrap(self.api_key, field="api_key", model="wsone.instance", pk=self.pk)
        self.client_secret = rewrap(self.client_secret, field="client_secret", model="wsone.instance", pk=self.pk)
        self.password = rewrap(self.password, field="password", model="wsone.instance", pk=self.pk)

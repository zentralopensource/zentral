import logging
from django.db import models
from django.db.models import F
from django.urls import reverse
import hashlib

from zentral.core.secret_engines import decrypt_str, encrypt_str, rewrap


logger = logging.getLogger("zentral.contrib.intune.models")


class Tenant(models.Model):
    business_unit = models.ForeignKey("inventory.BusinessUnit", on_delete=models.PROTECT)
    name = models.CharField(max_length=256, unique=True)
    description = models.TextField(blank=True)
    # Authentication
    tenant_id = models.CharField(max_length=256, unique=True, help_text="The microsoft Azure Tenant ID")
    client_id = models.UUIDField(unique=True, help_text="The client ID of your app registration")
    client_secret = models.TextField(help_text="The client secret of your app registration")
    # Versioning
    version = models.PositiveIntegerField(editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("intune:tenant", args=(self.pk,))

    def save(self, *args, **kwargs):
        if not self.pk:
            self.version = 0
        else:
            self.version = F("version") + 1
        super().save(*args, **kwargs)

    def serialize_for_event(self):
        data = self.get_client_secret().encode("utf-8")
        sha256_hash = hashlib.sha256()
        sha256_hash.update(data)
        client_secret_hash = sha256_hash.hexdigest()

        return {
            'business_unit': self.business_unit.pk,
            'name': self.name,
            'description': self.description,
            'tenant_id': self.tenant_id,
            'client_id': str(self.client_id),
            'client_secret_hash': client_secret_hash,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
        }

    # Secrets

    def set_client_secret(self, client_secret):
        if not self.pk:
            raise ValueError("Instance must have a PK")
        self.client_secret = encrypt_str(client_secret, field="client_secret", model="intune.tenant", pk=self.pk)

    def get_client_secret(self):
        if not self.pk:
            raise ValueError("Instance must have a PK")
        return decrypt_str(self.client_secret, field="client_secret", model="intune.tenant", pk=self.pk)

    def rewrap_secrets(self):
        if not self.pk:
            raise ValueError("Instance must have a PK")
        self.client_secret = rewrap(self.client_secret, field="client_secret", model="intune.tenant", pk=self.pk)

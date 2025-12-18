import hashlib
import logging
import uuid
from django.db import models
from django.urls import reverse
from zentral.contrib.inventory.models import Tag
from zentral.core.secret_engines import decrypt_str, encrypt_str, rewrap
from django.utils.translation import gettext_lazy as _


logger = logging.getLogger("zentral.contrib.google_worspace.models")


class ConnectionManager(models.Manager):
    def can_be_deleted(self):
        return self.filter(
            ~models.Exists(GroupTagMapping.objects.filter(connection=models.OuterRef("pk"))),
        )


class Connection(models.Model):
    class Type(models.TextChoices):
        OAUTH_ADMIN_SDK = "OAUTH", _("OAuth Admin SDK"),
        SERVICE_ACCOUNT_CLOUD_IDENTITY = "SA_CLOUD_ID", _("Service Account Could Identity")

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(unique=True)
    client_config = models.TextField(editable=False)
    user_info = models.TextField(null=True, editable=False)
    customer_id = models.CharField(blank=True, null=True)
    type = models.CharField(choices=Type, default=Type.OAUTH_ADMIN_SDK)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("google_workspace:connection", args=(self.pk,))

    # secrets

    def _get_secret_engine_kwargs(self, field):
        return {
            "model": "google_workspace.connection",
            "pk": str(self.pk),
            "field": field,
        }

    def get_client_config(self):
        if not self.client_config:
            return
        return decrypt_str(self.client_config, **self._get_secret_engine_kwargs("client_config"))

    def set_client_config(self, client_config):
        self.client_config = encrypt_str(client_config, **self._get_secret_engine_kwargs("client_config"))

    def get_user_info(self):
        if not self.user_info:
            return
        return decrypt_str(self.user_info, **self._get_secret_engine_kwargs("user_info"))

    def set_user_info(self, user_info):
        if user_info is None:
            self.user_info = None
            return
        self.user_info = encrypt_str(user_info, **self._get_secret_engine_kwargs("user_info"))

    def rewrap_secrets(self):
        self.client_config = rewrap(self.client_config, **self._get_secret_engine_kwargs("client_config"))
        self.user_info = rewrap(self.user_info, **self._get_secret_engine_kwargs("user_info"))

    def serialize_for_event(self, keys_only=False):
        d = {"pk": str(self.pk), "name": self.name}
        if keys_only:
            return d
        match self.type:
            case Connection.Type.OAUTH_ADMIN_SDK:
                d.update({"client_config_hash": hashlib.sha256(self.get_client_config().encode("utf-8")).hexdigest()})
            case Connection.Type.SERVICE_ACCOUNT_CLOUD_IDENTITY:
                d.update({"customer_id": self.customer_id})
        d.update({
            "type": self.type,
            "created_at": self.created_at,
            "updated_at": self.updated_at
            })
        return d

    def can_be_deleted(self):
        return Connection.objects.can_be_deleted().filter(pk=self.pk).exists()

    objects = ConnectionManager()


class GroupTagMapping(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    connection = models.ForeignKey(Connection, on_delete=models.CASCADE)
    group_email = models.EmailField()
    tags = models.ManyToManyField(Tag)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (("connection", "group_email"),)

    def get_absolute_url(self):
        return reverse("google_workspace:connection", args=(self.connection.pk,)) + f"#gtm-{self.pk}"

    def serialize_for_event(self, keys_only=False):
        d = {"pk": str(self.pk), "group_email": self.group_email}
        if keys_only:
            return d
        d.update({
            "connection": self.connection.serialize_for_event(keys_only=True),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "tags": [tag.serialize_for_event(keys_only=True) for tag in self.tags.all().order_by("name")]
            })
        return d

import logging
import uuid
from django.db import models
from zentral.utils.backend_model import BackendInstance
from django.contrib.auth.models import Group
from .backends.all import StoreBackend, get_store_backend


logger = logging.getLogger('zentral.core.stores.models')


class StoreManager(models.Manager):
    def not_provisioned(self):
        return self.filter(provisioning_uid__isnull=True)

    def for_deletion(self):
        return self.not_provisioned()

    def for_update(self):
        return self.not_provisioned()


class Store(BackendInstance):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    provisioning_uid = models.CharField(max_length=256, unique=True, null=True, editable=False)
    slug = models.SlugField(unique=True, editable=False)
    admin_console = models.BooleanField(verbose_name="Use for admin console", default=False)
    event_filters = models.JSONField(default=dict)
    events_url_authorized_roles = models.ManyToManyField(Group, blank=True, related_name="+")
    backend = models.CharField(choices=StoreBackend.choices)
    backend_enum = StoreBackend
    objects = StoreManager()

    def get_backend(self, load=False):
        return get_store_backend(self, load)

    def can_be_deleted(self):
        return Store.objects.for_deletion().filter(pk=self.pk).exists()

    def can_be_updated(self):
        return Store.objects.for_update().filter(pk=self.pk).exists()

    def serialize_for_event(self, keys_only=False):
        d = super().serialize_for_event(keys_only=keys_only)
        if not keys_only:
            if self.provisioning_uid:
                d["provisioning_uid"] = self.provisioning_uid
            d.update({
                "admin_console": self.admin_console,
                "event_filters": self.event_filters,
                "events_url_authorized_roles": [
                    {"pk": g.pk, "name": g.name}
                    for g in self.events_url_authorized_roles.all().order_by("name")
                ]
            })
        return d

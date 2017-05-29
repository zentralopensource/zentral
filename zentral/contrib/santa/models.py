import logging
from django.db import models
from zentral.contrib.inventory.models import Certificate, OSXApp
from zentral.utils.mt_models import AbstractMTObject, MTObjectManager

logger = logging.getLogger("zentral.contrib.santa.models")


class CollectedApplicationManager(MTObjectManager):
    def search(self, **kwargs):
        qs = self.all()
        name = kwargs.get("name")
        if name:
            qs = qs.filter(name__icontains=name)
            return qs.select_related("bundle").order_by("bundle__bundle_name", "name")
        else:
            return []


class CollectedApplication(AbstractMTObject):
    name = models.TextField()
    path = models.TextField()
    sha_256 = models.CharField(max_length=64, db_index=True)
    bundle = models.ForeignKey(OSXApp, blank=True, null=True, on_delete=models.PROTECT)
    bundle_path = models.TextField(blank=True, null=True)
    signed_by = models.ForeignKey(Certificate, blank=True, null=True, on_delete=models.PROTECT)

    objects = CollectedApplicationManager()

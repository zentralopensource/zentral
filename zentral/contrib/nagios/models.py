import logging
from django.db import models
from django.db.models import F
from django.utils.crypto import get_random_string


logger = logging.getLogger("zentral.contrib.nagios.models")


def make_secret():
    return get_random_string(71)


class NagiosInstance(models.Model):
    version = models.PositiveIntegerField(editable=False)
    business_unit = models.ForeignKey("inventory.BusinessUnit", on_delete=models.PROTECT, blank=True, null=True)
    url = models.URLField(unique=True)
    secret = models.CharField(max_length=256, editable=False, unique=True,
                              default=make_secret)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if not self.id:
            self.version = 0
        else:
            self.version = F("version") + 1
        super().save(*args, **kwargs)

import logging
from django.db import models


logger = logging.getLogger("zentral.contrib.okta.models")


class EventHook(models.Model):
    okta_domain = models.CharField(max_length=256)
    api_token = models.CharField(max_length=256)
    okta_id = models.CharField(max_length=256, null=True)

    name = models.CharField(max_length=256)
    authorization_key = models.CharField(max_length=64, unique=True)

    class Meta:
        unique_together = ('okta_domain', 'name')

    def __str__(self):
        return "{}/{}".format(self.okta_domain, self.name)

    def observer_dict(self):
        return {"hostname": self.okta_domain,
                "vendor": "Okta",
                "type": "EventHook",
                "content_type": "okta.eventhook",
                "pk": self.pk}

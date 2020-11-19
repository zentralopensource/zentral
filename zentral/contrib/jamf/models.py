import logging
import os.path
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models
from django.db.models import F
from django.urls import reverse
from django.utils.crypto import get_random_string


logger = logging.getLogger("zentral.contrib.jamf.models")


def make_secret():
    return get_random_string(67)


class JamfInstance(models.Model):
    version = models.PositiveIntegerField(editable=False)
    business_unit = models.ForeignKey("inventory.BusinessUnit", on_delete=models.PROTECT, blank=True, null=True)
    host = models.CharField(max_length=256,
                            help_text="host name of the server")
    port = models.IntegerField(validators=[MinValueValidator(1),
                                           MaxValueValidator(65535)],
                               default=8443,
                               help_text="server port number")
    path = models.CharField(max_length=64, default="/JSSResource",
                            help_text="path of the server API")
    user = models.CharField(max_length=64,
                            help_text="API user name")
    password = models.CharField(max_length=256,
                                help_text="API user password")
    secret = models.CharField(max_length=256, editable=False, unique=True,
                              default=make_secret)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('host', 'port', 'path')

    def __str__(self):
        return self.host

    def get_absolute_url(self):
        return reverse("jamf:jamf_instance", args=(self.pk,))

    def save(self, *args, **kwargs):
        if not self.id:
            self.version = 0
        else:
            self.version = F("version") + 1
        super().save(*args, **kwargs)

    def base_url(self):
        return "https://{}:{}".format(self.host, self.port)

    def api_base_url(self):
        return "{}{}".format(self.base_url(), self.path)

    def api_doc_url(self):
        return "{}{}".format(self.base_url(), os.path.join(self.path, "../api"))

    def serialize(self):
        d = {
            "pk": self.pk,
            "version": self.version,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "user": self.user,
            "password": self.password,
            "secret": self.secret,
            "tag_configs": [tm.serialize() for tm in self.tagconfig_set.select_related("taxonomy").all()],
        }
        if self.business_unit:
            d["business_unit"] = self.business_unit.serialize()
        return d

    def observer_dict(self):
        return {"hostname": self.host,
                "vendor": "Jamf",
                "type": "Jamf Pro",
                "content_type": "jamf.jamfinstance",
                "pk": self.pk}


class TagConfig(models.Model):
    GROUP_SOURCE = "GROUP"
    SOURCE_CHOICES = (
        (GROUP_SOURCE, "Group"),
    )
    instance = models.ForeignKey(JamfInstance, on_delete=models.CASCADE)
    source = models.CharField(max_length=16, choices=SOURCE_CHOICES, default=GROUP_SOURCE)
    taxonomy = models.ForeignKey("inventory.Taxonomy", on_delete=models.CASCADE)
    regex = models.CharField(
        max_length=256,
        help_text="matching names will be used to automatically generate tags"
    )
    replacement = models.CharField(
        max_length=32,
        help_text="replacement pattern used to generate a tag name from a tag regex match"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def get_absolute_url(self):
        return "{}#tag-config-{}".format(self.instance.get_absolute_url(), self.pk)

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        self.instance.save()

    def serialize(self):
        return {"source": self.source,
                "taxonomy_id": self.taxonomy.id,
                "regex": self.regex,
                "replacement": self.replacement}

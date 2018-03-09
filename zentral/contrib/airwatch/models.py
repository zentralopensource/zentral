import logging
from django.db import models
from django.contrib.postgres.fields import JSONField


logger = logging.getLogger("zentral.contrib.airwatch.models")


class AirwatchInstance(models.Model):
    business_unit = models.ForeignKey("inventory.BusinessUnit", models.PROTECT)
    api_key = models.TextField()
    account_name = models.TextField(editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "{} Airwatch instance".format(self.account_name)


class AirwatchApp(models.Model):
    airwatch_instance = models.ForeignKey(AirwatchInstance)
    name = models.CharField(max_length=256)
    airwatch_id = models.IntegerField('Airwatch ID')
    builder = models.CharField(max_length=256)
    build_kwargs = JSONField('Builder parameters')
    created_at = models.DateTimeField(auto_now_add=True)

    def get_builder_class(self):
        from zentral.utils.osx_package import get_standalone_package_builders
        return get_standalone_package_builders()[self.builder]

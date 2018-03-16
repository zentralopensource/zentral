import logging
from django.db import models
from django.contrib.postgres.fields import JSONField
from django.core.validators import MinValueValidator, MaxValueValidator


logger = logging.getLogger("zentral.contrib.airwatch.models")


class AirwatchInstance(models.Model):
    business_unit = models.ForeignKey("inventory.BusinessUnit", models.PROTECT)
    host = models.CharField(max_length=256, default="https://airwatch.vmtestdrive.com",
                            help_text="host name of the server")
    port = models.IntegerField(validators=[MinValueValidator(1),
                                           MaxValueValidator(65535)],
                               default=443,
                               help_text="server port number")
    path = models.CharField(max_length=64, default="/api",
                            help_text="path of the server API")
    user = models.CharField(max_length=64, help_text="API user name")
    password = models.CharField(max_length=256, help_text="API user password")
    aw_tenant_code = models.CharField(max_length=256, help_text="Airwatch tenant code")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "{} Airwatch instance".format(self.user)

    def base_url(self):
        return "https://{}:{}".format(self.host, self.port)

    def api_base_url(self):
        return "{}{}".format(self.base_url(), self.path)


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

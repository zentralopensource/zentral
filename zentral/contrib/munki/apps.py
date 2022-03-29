from zentral.utils.apps import ZentralAppConfig


class ZentralMunkiAppConfig(ZentralAppConfig):
    name = "zentral.contrib.munki"
    default = True
    verbose_name = "Zentral Munki contrib app"
    permission_models = ("configuration", "enrollment")

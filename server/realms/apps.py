from zentral.utils.apps import ZentralAppConfig


class ZentralRealmsAppConfig(ZentralAppConfig):
    name = "realms"
    default = True
    verbose_name = "Zentral realms app"
    permission_models = ("realm", "realmgroupmapping")

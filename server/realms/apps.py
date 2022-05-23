import os.path
from zentral.utils.apps import ZentralAppConfig


class ZentralRealmsAppConfig(ZentralAppConfig):
    name = "realms"
    path = os.path.realpath(os.path.join(os.path.dirname(__file__)))  # because this package is a namespace package
    default = True
    verbose_name = "Zentral realms app"
    permission_models = ("realm", "realmgroupmapping")

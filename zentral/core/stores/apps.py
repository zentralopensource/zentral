import os.path
from zentral.utils.apps import ZentralAppConfig


class ZentralStoresAppConfig(ZentralAppConfig):
    name = "zentral.core.stores"
    # path required because of ee/
    path = os.path.dirname(os.path.abspath(__file__))
    default = True
    verbose_name = "Zentral stores app"
    permission_models = ("store",)

from django.apps import apps
from accounts.pbac.engine import engine
from zentral.utils.apps import ZentralAppConfig


class ZentralAccountsAppConfig(ZentralAppConfig):
    name = "accounts"
    default = True
    verbose_name = "Zentral accounts app"
    permission_models = ("apitoken", "oidcapitokenissuer", "policy", "user")

    def register_legacy_perms(self):
        super().register_legacy_perms()
        engine.register_app_legacy_perms(apps.get_app_config("auth"))

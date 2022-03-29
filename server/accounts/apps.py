from zentral.utils.apps import ZentralAppConfig


class ZentralAccountsAppConfig(ZentralAppConfig):
    name = "accounts"
    default = True
    verbose_name = "Zentral accounts app"
    permission_models = ("user",)

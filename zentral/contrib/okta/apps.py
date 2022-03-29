from zentral.utils.apps import ZentralAppConfig


class ZentralOktaAppConfig(ZentralAppConfig):
    name = "zentral.contrib.okta"
    default = True
    verbose_name = "Zentral okta contrib app"

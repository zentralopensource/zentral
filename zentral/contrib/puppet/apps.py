from zentral.utils.apps import ZentralAppConfig


class ZentralPuppetAppConfig(ZentralAppConfig):
    name = "zentral.contrib.puppet"
    default = True
    verbose_name = "Zentral Puppet contrib app"
    permission_models = (
        "instance",
    )

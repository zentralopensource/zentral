from zentral.utils.apps import ZentralAppConfig


class ZentralWSOneAppConfig(ZentralAppConfig):
    name = "zentral.contrib.wsone"
    default = True
    verbose_name = "Zentral Workspace One contrib app"
    permission_models = (
        "instance",
    )

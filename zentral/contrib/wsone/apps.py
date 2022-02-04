from zentral.utils.apps import ZentralAppConfig


class ZentralWSOneAppConfig(ZentralAppConfig):
    name = "zentral.contrib.wsone"
    verbose_name = "Zentral Workspace One contrib app"
    permission_models = (
        "instance",
    )

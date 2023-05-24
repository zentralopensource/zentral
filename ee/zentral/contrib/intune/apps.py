from zentral.utils.apps import ZentralAppConfig


class ZentralIntuneAppConfig(ZentralAppConfig):
    name = 'zentral.contrib.intune'
    default = True
    verbose_name = "Microsoft Intune contrib app"
    permission_models = (
        "tenant",
    )

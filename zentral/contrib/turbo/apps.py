from zentral.utils.apps import ZentralAppConfig


class ZentralTurboAppConfig(ZentralAppConfig):
    name = "zentral.contrib.turbo"
    default = True
    verbose_name = "Zentral Turbo contrib app"
    permission_models = ("configuration", "enrolledmachine", "enrollment", "fileexport", "mscpcheck",
                         "onetimejob", "recurringjob", "script", "sysdiagnose")

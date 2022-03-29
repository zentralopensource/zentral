from zentral.utils.apps import ZentralAppConfig


class ZentralNagiosAppConfig(ZentralAppConfig):
    name = "zentral.contrib.nagios"
    default = True
    verbose_name = "Zentral Nagios contrib app"

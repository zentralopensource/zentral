from zentral.utils.apps import ZentralAppConfig


class ZentralFilebeatAppConfig(ZentralAppConfig):
    name = "zentral.contrib.filebeat"
    default = True
    verbose_name = "Zentral Filebeat contrib app"

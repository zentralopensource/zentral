from zentral.utils.apps import ZentralAppConfig


class ZentralWatchersAppConfig(ZentralAppConfig):
    name = "zentral.core.watchers"
    default = True
    verbose_name = "Zentral watchers app"

from zentral.utils.apps import ZentralAppConfig


class ZentralProbesAppConfig(ZentralAppConfig):
    name = "zentral.core.probes"
    default = True
    verbose_name = "Zentral probes app"
    permission_models = ("feed", "feedprobe", "probesource")

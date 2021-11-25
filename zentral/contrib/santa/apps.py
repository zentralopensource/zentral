from zentral.utils.apps import ZentralAppConfig


class ZentralSantaAppConfig(ZentralAppConfig):
    name = "zentral.contrib.santa"
    verbose_name = "Zentral Santa contrib app"
    permission_models = ("configuration", "enrollment", "rule", "ruleset", "target")

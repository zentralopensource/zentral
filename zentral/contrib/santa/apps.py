from zentral.utils.apps import ZentralAppConfig


class ZentralSantaAppConfig(ZentralAppConfig):
    name = "zentral.contrib.santa"
    default = True
    verbose_name = "Zentral Santa contrib app"
    permission_models = (
        "ballot",
        "configuration",
        "enrollment",
        "rule",
        "ruleset",
        "target",
        "votinggroup",
    )

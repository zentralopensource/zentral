from zentral.utils.apps import ZentralAppConfig


class ZentralInventoryAppConfig(ZentralAppConfig):
    name = "zentral.contrib.inventory"
    default = True
    verbose_name = "Zentral inventory contrib app"
    permission_models = (
        "androidapp",
        "businessunit",
        "debpackage",
        "file",
        "iosapp",
        "jmespathcheck",
        "link",
        "machinegroup",
        "machinesnapshot",
        "metabusinessunit",
        "osxapp",
        "osxappinstance",
        "program",
        "programinstance",
        "tag",
        "taxonomy",
    )

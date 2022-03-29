from zentral.utils.apps import ZentralAppConfig


class ZentralInventoryAppConfig(ZentralAppConfig):
    name = "zentral.contrib.inventory"
    default = True
    verbose_name = "Zentral inventory contrib app"
    permission_models = (
        "androidapp",
        "bunsinessunit",
        "debpackage",
        "file",
        "iosapp",
        "jmespathcheck",
        "link",
        "machinegroup",
        "machinesnapshot",
        "machinetag",
        "metabusinessunit",
        "metabusinessunittag",
        "osxapp",
        "osxappinstance",
        "program",
        "programinstance",
        "tag",
        "taxonomy",
    )

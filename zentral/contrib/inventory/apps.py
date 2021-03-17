from zentral.utils.apps import ZentralAppConfig


class ZentralInventoryAppConfig(ZentralAppConfig):
    name = "zentral.contrib.inventory"
    verbose_name = "Zentral inventory contrib app"
    permission_models = (
        "bunsinessunit",
        "debpackage",
        "file",
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

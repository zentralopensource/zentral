from zentral.utils.apps import ZentralAppConfig


class ZentralInventoryAppConfig(ZentralAppConfig):
    name = "zentral.contrib.inventory"
    verbose_name = "Zentral inventory contrib app"
    permission_models = (
        "bunsinessunit",
        "file",
        "link",
        "machinegroup",
        "machinesnapshot",
        "machinetag",
        "metabusinessunit",
        "metabusinessunittag",
        "osxapp",
        "osxappinstance",
        "tag",
        "taxonomy",
    )

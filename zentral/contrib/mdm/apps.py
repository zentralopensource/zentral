from zentral.utils.apps import ZentralAppConfig


class ZentralMDMAppConfig(ZentralAppConfig):
    name = "zentral.contrib.mdm"
    default = True
    verbose_name = "Zentral MDM contrib app"
    permission_models = (
        "artifact",
        "asset",
        "blueprint",
        "blueprintartifact",
        "depdevice",
        "depenrollment",
        "depvirtualserver",
        "deviceartifact",
        "enrolleddevice",
        "enrolleduser",
        "enterpriseapp",
        "filevaultconfig",
        "location",
        "profile",
        "pushcertificate",
        "otaenrollment",
        "scepconfig",
        "userartifact",
        "userenrollment",
    )

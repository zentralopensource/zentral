from zentral.utils.apps import ZentralAppConfig


class ZentralMDMAppConfig(ZentralAppConfig):
    name = "zentral.contrib.mdm"
    default = True
    verbose_name = "Zentral MDM contrib app"
    permission_models = (
        "artifact",
        "artifactversion",
        "asset",
        "blueprint",
        "blueprintartifact",
        "dataasset",
        "declaration",
        "depdevice",
        "depenrollment",
        "depenrollmentcustomview",
        "depvirtualserver",
        "deviceartifact",
        "devicecommand",
        "enrolleddevice",
        "enrolleduser",
        "enrollmentcustomview",
        "enterpriseapp",
        "filevaultconfig",
        "location",
        "profile",
        "pushcertificate",
        "otaenrollment",
        "realmgrouptagmapping",
        "recoverypasswordconfig",
        "scepconfig",
        "softwareupdate",
        "softwareupdateenforcement",
        "userartifact",
        "usercommand",
        "userenrollment",
    )

    def ready(self):
        super().ready()
        from realms.models import realm_group_members_updated
        from .inventory import realm_group_members_updated_receiver
        realm_group_members_updated.connect(realm_group_members_updated_receiver)

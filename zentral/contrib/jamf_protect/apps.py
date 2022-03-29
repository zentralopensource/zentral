from zentral.utils.apps import ZentralAppConfig


class ZentralJamfProtectAppConfig(ZentralAppConfig):
    name = "zentral.contrib.jamf_protect"
    default = True
    verbose_name = "Zentral Jamf Protect contrib app"

from zentral.utils.apps import ZentralAppConfig


class ZentralGoogleWorkspaceAppConfig(ZentralAppConfig):
    name = "zentral.contrib.google_workspace"
    default = True
    verbose_name = "Zentral Google Workspace contrib app"
    permission_models = ("connection", "grouptagmapping")

from zentral.utils.apps import ZentralAppConfig


class ZentralTerraformAppConfig(ZentralAppConfig):
    name = "zentral.core.terraform"
    default = True
    verbose_name = "Zentral Terraform core app"
    permission_models = ("state",)

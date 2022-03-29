from zentral.utils.apps import ZentralAppConfig


class ZentralComplianceChecksAppConfig(ZentralAppConfig):
    name = "zentral.core.compliance_checks"
    default = True
    verbose_name = "Zentral compliance checks app"
    permission_models = ("compliancecheck", "machinestatus")

from . import register_compliance_check_class


class BaseComplianceCheck:
    model_display = "Compliance check"
    required_view_permissions = ()

    @classmethod
    def get_model(cls):
        return cls.__name__

    def __init__(self, compliance_check):
        self.compliance_check = compliance_check
        self.pk = compliance_check.pk

    def get_redirect_url(self):
        raise NotImplementedError


register_compliance_check_class(BaseComplianceCheck)

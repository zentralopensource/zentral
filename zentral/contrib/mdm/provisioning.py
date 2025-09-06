from .serializers import ACMEIssuerSerializer, PushCertificateSerializer, SCEPIssuerSerializer
from zentral.utils.provisioning import Provisioner


class ACMEIssuerProvisioner(Provisioner):
    config_key = "acme_issuers"
    serializer_class = ACMEIssuerSerializer


class PushCertificateProvisioner(Provisioner):
    config_key = "push_certificates"
    serializer_class = PushCertificateSerializer


class SCEPIssuerProvisioner(Provisioner):
    config_key = "scep_issuers"
    serializer_class = SCEPIssuerSerializer

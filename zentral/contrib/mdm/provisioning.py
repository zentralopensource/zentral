from .serializers import PushCertificateSerializer, SCEPConfigSerializer
from zentral.utils.provisioning import Provisioner


class PushCertificateProvisioner(Provisioner):
    config_key = "push_certificates"
    serializer_class = PushCertificateSerializer


class SCEPConfigProvisioner(Provisioner):
    config_key = "scep_configs"
    serializer_class = SCEPConfigSerializer

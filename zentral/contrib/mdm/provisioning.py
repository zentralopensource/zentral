from .serializers import SCEPConfigSerializer
from zentral.utils.provisioning import Provisioner


class SCEPConfigProvisioner(Provisioner):
    config_key = "scep_configs"
    serializer_class = SCEPConfigSerializer

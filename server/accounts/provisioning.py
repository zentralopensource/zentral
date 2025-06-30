import logging
from zentral.utils.provisioning import Provisioner
from .serializers import RoleSerializer


logger = logging.getLogger("zentral.accounts.provisioning")


class RoleProvisioner(Provisioner):
    config_key = "roles"
    serializer_class = RoleSerializer

    def get_instance_by_uid(self, uid):
        try:
            return self.model.objects.select_for_update().get(provisioned_role__provisioning_uid=uid)
        except self.model.DoesNotExist:
            pass

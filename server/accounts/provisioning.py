import logging
from django.db import transaction
from zentral.utils.provisioning import Provisioner
from .serializers import PolicyProvisioningSerializer, RoleSerializer
from .pbac.utils import signal_policy_change


logger = logging.getLogger("zentral.accounts.provisioning")


class RoleProvisioner(Provisioner):
    config_key = "roles"
    serializer_class = RoleSerializer

    def get_instance_by_uid(self, uid):
        try:
            return self.model.objects.select_for_update().get(provisioned_role__provisioning_uid=uid)
        except self.model.DoesNotExist:
            pass


class PolicyProvisioner(Provisioner):
    config_key = "policies"
    serializer_class = PolicyProvisioningSerializer
    depends_on = (RoleProvisioner,)

    def create_instance(self, uid, spec):
        policy = super().create_instance(uid, spec)
        if not policy:
            return
        transaction.on_commit(signal_policy_change)

    def update_instance(self, policy, uid, spec):
        super().update_instance(policy, uid, spec)
        transaction.on_commit(signal_policy_change)

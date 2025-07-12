import logging
from django.db import transaction
from accounts.provisioning import RoleProvisioner
from base.notifier import notifier
from zentral.utils.provisioning import Provisioner
from .serializers import StoreProvisioningSerializer


logger = logging.getLogger("zentral.core.stores.provisioning")


class StoreProvisioner(Provisioner):
    config_key = "stores"
    serializer_class = StoreProvisioningSerializer
    depends_on = (RoleProvisioner,)

    def create_instance(self, uid, spec):
        db_store = super().create_instance(uid, spec)

        if not db_store:
            return

        def notify():
            notifier.send_notification("stores.store", str(db_store.pk))

        transaction.on_commit(notify)

    def update_instance(self, db_store, uid, spec):
        super().update_instance(db_store, uid, spec)

        def notify():
            notifier.send_notification("stores.store", str(db_store.pk))

        transaction.on_commit(notify)

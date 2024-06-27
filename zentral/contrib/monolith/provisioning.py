import logging
from django.db import transaction
from base.notifier import notifier
from zentral.utils.provisioning import Provisioner
from .repository_backends import load_repository_backend
from .serializers import RepositorySerializer


logger = logging.getLogger("zentral.contrib.monolith.provisioning")


class RepositoryProvisioner(Provisioner):
    config_key = "repositories"
    serializer_class = RepositorySerializer

    def create_instance(self, uid, spec):
        db_repository = super().create_instance(uid, spec)
        if not db_repository:
            return

        repository = load_repository_backend(db_repository)
        try:
            repository.sync_catalogs()
        except Exception:
            logger.error("Could not sync provisioned repository %s", db_repository.provisioning_uid)

        def notify():
            notifier.send_notification("monolith.repository", str(db_repository.pk))

        transaction.on_commit(notify)

    def update_instance(self, db_repository, uid, spec):
        super().update_instance(db_repository, uid, spec)

        def notify():
            notifier.send_notification("monolith.repository", str(db_repository.pk))

        transaction.on_commit(notify)

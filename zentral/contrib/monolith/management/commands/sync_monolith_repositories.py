from functools import partial

from django.db import transaction
from django.core.management.base import BaseCommand
from base.notifier import notifier
from zentral.contrib.monolith.models import Repository
from zentral.contrib.monolith.repository_backends import load_repository_backend
from zentral.contrib.monolith.tasks import try_lock_repository_sync
from zentral.core.queues import queues


class Command(BaseCommand):
    help = 'Sync Monolith repositories'

    def write(self, msg):
        if self.verbosity:
            self.stdout.write(msg)

    def handle(self, *args, **kwargs):
        self.verbosity = kwargs.get("verbosity", 1)
        for db_repository in Repository.objects.all():
            repository = load_repository_backend(db_repository)
            self.write(f"Sync {repository.name} repository")
            # the try must stay outside the atomic block: the exception has to reach __exit__ to
            # roll this repository back and to release its transaction scoped advisory lock
            try:
                with transaction.atomic():
                    if not try_lock_repository_sync(db_repository.pk):
                        self.stderr.write(f"Could not sync {repository.name}: a sync is already running")
                        continue
                    repository.sync_catalogs()
            except Exception as e:
                self.stderr.write(f"Could not sync {repository.name}: {e}")
            else:
                self.write("OK")
                transaction.on_commit(
                    partial(notifier.send_notification, "monolith.repository", str(db_repository.pk))
                )
        queues.stop()

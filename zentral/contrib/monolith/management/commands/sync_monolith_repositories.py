from django.db import transaction
from django.core.management.base import BaseCommand
from base.notifier import notifier
from zentral.contrib.monolith.models import Repository
from zentral.contrib.monolith.repository_backends import load_repository_backend


class Command(BaseCommand):
    help = 'Sync Monolith repositories'

    def write(self, msg):
        if self.verbosity:
            self.stdout.write(msg)

    def handle(self, *args, **kwargs):
        self.verbosity = kwargs.get("verbosity", 1)
        with transaction.atomic():
            for db_repository in Repository.objects.all():
                repository = load_repository_backend(db_repository)
                self.write(f"Sync {repository.name} repository")
                try:
                    repository.sync_catalogs()
                except Exception as e:
                    self.stderr.write(f"Could not sync {repository.name}: {e}")
                else:
                    self.write("OK")

                    def notify():
                        notifier.send_notification("monolith.repository", str(db_repository.pk))

                    transaction.on_commit(notify)

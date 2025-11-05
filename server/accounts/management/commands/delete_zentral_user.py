import sys
from django.core.management.base import BaseCommand
from django.db import transaction
from accounts.models import User
from zentral.core.events.base import AuditEvent
from zentral.core.queues import queues


class Command(BaseCommand):
    help = 'Delete a Zentral user or service account.'

    def add_arguments(self, parser):
        parser.add_argument('username')

    def handle(self, *args, **kwargs):
        try:
            username = kwargs["username"]
            with transaction.atomic():
                try:
                    user = User.objects.get(username=username)
                except User.DoesNotExist:
                    self.stderr.write("0 users deleted")
                    sys.exit(11)
                else:
                    event = AuditEvent.build(
                        user,
                        action=AuditEvent.Action.DELETED,
                        prev_value=user.serialize_for_event())

                    user.delete()

                    def on_commit_callback():
                        event.post()

                    transaction.on_commit(on_commit_callback)
                    self.stdout.write("1 user deleted")
        finally:
            queues.stop()

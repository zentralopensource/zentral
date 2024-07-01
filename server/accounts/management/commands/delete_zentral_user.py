import sys
from django.core.management.base import BaseCommand
from accounts.models import User


class Command(BaseCommand):
    help = 'Delete a Zentral user or service account.'

    def add_arguments(self, parser):
        parser.add_argument('username')

    def handle(self, *args, **kwargs):
        username = kwargs["username"]
        deleted_objects_count, _ = User.objects.filter(username=username).delete()
        if not deleted_objects_count:
            self.stderr.write("0 users deleted")
            sys.exit(11)
        else:
            self.stdout.write("1 user deleted")

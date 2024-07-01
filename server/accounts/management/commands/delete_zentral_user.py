import sys
from django.core.management.base import BaseCommand
from accounts.models import User


class Command(BaseCommand):
    help = 'Delete a Zentral user or service account.'

    def add_arguments(self, parser):
        parser.add_argument('username')

    def handle(self, *args, **kwargs):
        username = kwargs["username"]
        deleted_user_count, _ = User.objects.filter(username=username).delete()
        if deleted_user_count == 0:
            self.stderr.write("0 users deleted")
            sys.exit(11)
        else:
            self.stdout.write(f"{deleted_user_count} user(s) deleted")

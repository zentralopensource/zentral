import json
from django.core.management.base import BaseCommand
from accounts.utils import all_permissions


class Command(BaseCommand):
    help = 'List the Zentral permissions.'

    def add_arguments(self, parser):
        parser.add_argument('--json', action="store_true",
                            help="JSON output")
        parser.add_argument('--read-only', action="store_true",
                            help="Only include read-only permissions")
        parser.add_argument('--no-custom', action="store_true",
                            help="Do not include custom permissions")

    def handle(self, *args, **kwargs):
        read_only = kwargs.get("read_only", False)
        no_custom = kwargs.get("no_custom", False)
        permissions = []
        for permission, permission_ro, permission_cus in all_permissions():
            if read_only and not permission_ro:
                continue
            if no_custom and permission_cus:
                continue
            permissions.append(f"{permission.content_type.app_label}.{permission.codename}")
        if kwargs.get("json", False):
            permissions = json.dumps(permissions, indent=2)
            self.stdout.write(permissions)
        else:
            self.stdout.write("\n".join(permissions))

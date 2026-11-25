import json
from django.core.management.base import BaseCommand
from accounts.models import User


class Command(BaseCommand):
    help = 'List the Zentral users.'

    def add_arguments(self, parser):
        parser.add_argument('--json', action="store_true",
                            help="JSON output")
        parser.add_argument('--role', type=str, action='append',
                            help="Role name. If not specified, all users are listed")

    def handle(self, *args, **kwargs):
        user_qs = User.objects.all().order_by("username")
        if kwargs["role"]:
            user_qs = user_qs.distinct().filter(groups__name__in=kwargs["role"])
        if kwargs.get("json", False):
            output = [
                {"id": u.pk,
                 "username": u.username,
                 "email": u.email,
                 "is_active": u.is_active,
                 "is_superuser": u.is_superuser,
                 "is_remote": u.is_remote,
                 "is_service_account": u.is_service_account,
                 "roles": sorted(g.name for g in u.groups.all())}
                for u in user_qs.prefetch_related("groups")
            ]
            self.stdout.write(json.dumps(output, indent=2))
        else:
            self.stdout.write("\n".join(str(u) for u in user_qs))

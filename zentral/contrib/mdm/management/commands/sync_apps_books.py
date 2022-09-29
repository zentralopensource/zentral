from django.core.management.base import BaseCommand
from zentral.contrib.mdm.models import ServerToken
from zentral.contrib.mdm.apps_books import sync_assets


class Command(BaseCommand):
    help = 'Sync apps & books'

    def add_arguments(self, parser):
        parser.add_argument('--list-server-tokens', action='store_true', dest='list_server_tokens', default=False,
                            help='list existing server tokens')
        parser.add_argument('--server', dest='server_token_ids', type=int, nargs=1,
                            help='sync DEP virtual server devices')

    def handle(self, *args, **kwargs):
        if kwargs.get('list_server_tokens'):
            print("Existing server tokens:")
            for server_token in ServerToken.objects.all():
                print(server_token.pk, server_token)
            return
        server_token_qs = ServerToken.objects.all()
        server_token_ids = kwargs.get("server_token_ids")
        if server_token_ids:
            server_token_qs = server_token_qs.filter(pk__in=server_token_ids)
        for server_token in server_token_qs:
            print("Sync apps & books for server", server_token.pk, server_token)
            sync_assets(server_token)

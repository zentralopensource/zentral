import logging
import pprint
from django.core.management.base import BaseCommand, CommandError
from zentral.contrib.inventory.clients import clients

logger = logging.getLogger("zentral.contrib.inventory.management.commands.debug_inventory_clients")


class Command(BaseCommand):
    help = "Debug inventory clients"

    def add_arguments(self, parser):
        parser.add_argument('--list', action='store_true', dest='list_client', default=False, help='list clients')
        parser.add_argument('--get-machines', dest='client_id', type=int, nargs=1, help='get client machines')

    def handle(self, *args, **kwargs):
        if kwargs.get("list_client"):
            print("Configured clients:")
            for idx, client in enumerate(clients):
                print(idx)
                for key, val in client.source.items():
                    print(key, val)
        client_id = kwargs.get("client_id")
        if client_id:
            client_id = client_id[0]
            try:
                client = clients[client_id]
            except IndexError:
                raise CommandError("Client {} does not exist".format(client_id))
            for tree in client.get_machines():
                pprint.pprint(tree)

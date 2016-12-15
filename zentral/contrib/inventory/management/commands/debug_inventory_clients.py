import logging
import pprint
from django.core.management.base import BaseCommand, CommandError
from zentral.contrib.inventory.clients import clients

logger = logging.getLogger("zentral.contrib.inventory.management.commands.debug_inventory_clients")


class Command(BaseCommand):
    help = "Debug inventory clients"

    def add_arguments(self, parser):
        parser.add_argument('--list-clients', action='store_true', dest='list_clients', default=False,
                            help='list clients')
        parser.add_argument('--client', dest='client_id', type=int, nargs=1,
                            help='get client machines')
        parser.add_argument('--serial-number', dest='serial_number', type=str, nargs=1,
                            help='get client machine by serial_number')

    def handle(self, *args, **kwargs):
        if kwargs.get("list_clients"):
            print("Configured clients:")
            for idx, client in enumerate(clients):
                print(idx)
                for key, val in client.source.items():
                    print(key, val)
        client_id = kwargs.get("client_id")
        serial_number = kwargs.get("serial_number")
        if client_id:
            client_id = client_id[0]
            if serial_number:
                serial_number = serial_number[0]
            try:
                client = clients[client_id]
            except IndexError:
                raise CommandError("Client {} does not exist".format(client_id))
            n = 0
            for tree in client.get_machines():
                n += 1
                if serial_number is None or tree.get("serial_number") == serial_number:
                    pprint.pprint(tree)
            print(n, "MACHINES")

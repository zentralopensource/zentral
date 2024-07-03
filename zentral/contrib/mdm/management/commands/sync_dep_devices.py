from django.core.management.base import BaseCommand
from zentral.contrib.mdm.models import DEPVirtualServer
from zentral.contrib.mdm.dep import sync_dep_virtual_server_devices, DEPClientError


class Command(BaseCommand):
    help = 'Sync DEP devices'

    def add_arguments(self, parser):
        parser.add_argument('--list-servers', action='store_true', dest='list_servers', default=False,
                            help='list existing DEP virtual servers')
        parser.add_argument('--server', dest='server_ids', type=int, nargs=1,
                            help='sync DEP virtual server devices')
        parser.add_argument('--full-sync', action='store_true', dest='full_sync', default=False,
                            help='force a full sync')

    def write(self, msg):
        if self.verbosity:
            self.stdout.write(msg)

    def handle(self, *args, **kwargs):
        self.verbosity = kwargs.get("verbosity", 1)
        depvs_qs = DEPVirtualServer.objects.all().order_by("pk")
        if kwargs.get('list_servers'):
            self.write("Existing DEP virtual servers:")
            for server in depvs_qs:
                self.write(f"{server.id} {server}")
            return
        server_ids = kwargs.get("server_ids")
        if server_ids:
            depvs_qs = DEPVirtualServer.objects.filter(pk__in=server_ids)
        full_sync = kwargs.get("full_sync")
        for server in depvs_qs:
            self.write(f"Sync server {server.pk} {server}")
            try:
                for dep_device, created in sync_dep_virtual_server_devices(server, force_fetch=full_sync):
                    operation = "Created" if created else "Updated"
                    self.write(f"{operation} {dep_device}")
            except DEPClientError as e:
                if e.error_code == "EXPIRED_CURSOR":
                    self.write("Expired cursor → full sync")
                    for dep_device, created in sync_dep_virtual_server_devices(server, force_fetch=True):
                        operation = "Created" if created else "Updated"
                        self.write(f"{operation} {dep_device}")
                else:
                    self.stderr.write(f"DEP client error: {e}")
            except Exception as e:
                self.stderr.write(f"Unknown error: {e}")

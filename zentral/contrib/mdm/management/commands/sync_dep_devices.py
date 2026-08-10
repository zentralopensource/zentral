from django.core.management.base import BaseCommand
from django.db import transaction
from zentral.contrib.mdm.models import DEPVirtualServer
from zentral.contrib.mdm.dep import (
    DEPClientError,
    assign_dep_virtual_server_default_enrollment,
    sync_dep_virtual_server_devices,
    try_lock_dep_virtual_server_sync,
)


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
            with transaction.atomic():
                if not try_lock_dep_virtual_server_sync(server.pk):
                    self.write("Already being synced → skipped")
                    continue
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
            if not server.default_enrollment_id:
                continue
            # the task the API view schedules is run inline: this command is the cron entry point,
            # and it must not depend on a worker being up to assign the default enrollment
            try:
                operations = assign_dep_virtual_server_default_enrollment(server)
            except Exception as e:
                self.stderr.write(f"Could not assign the default enrollment: {e}")
            else:
                self.write("Assigned the default enrollment to {assigned} device(s),"
                           " {failed} failure(s)".format(**operations))

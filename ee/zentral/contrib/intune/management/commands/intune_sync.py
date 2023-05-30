import logging
from django.core.management.base import BaseCommand, CommandError
from zentral.contrib.intune.api_client import Client
from zentral.contrib.intune.models import Tenant
from zentral.contrib.intune.tasks import do_sync_inventory

logger = logging.getLogger("zentral.contrib.intune.management.commands.intune_sync")


class Command(BaseCommand):
    help = "Synchronize MS Intune Inventory"

    def add_arguments(self, parser):
        parser.add_argument('--list-tenants', action='store_true', dest='list_tenants', default=False,
                            help='list MS Intune Tenants')
        parser.add_argument('--tenant', dest='tenant_id', help='MS Intune Tenant ID')

    def handle(self, *args, **kwargs):
        if kwargs.get("list_tenants"):
            for tenant in Tenant.objects.all().order_by("name"):
                print("Name:", tenant.name, "UUID:", tenant.tenant_id)
            return
        tenant_id = kwargs.get("tenant_id")
        if not tenant_id:
            return
        try:
            tenant = Tenant.objects.get(tenant_id=tenant_id)
        except Tenant.DoesNotExist:
            raise CommandError(f"MS Intune tenant with tenant_id {tenant_id} does not exist")
        client = Client.from_tenant(tenant)
        result = do_sync_inventory(client)
        for key, val in result.items():
            print(f"{key}: {val}")

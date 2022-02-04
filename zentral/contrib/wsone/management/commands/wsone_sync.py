import logging
from django.core.management.base import BaseCommand, CommandError
from zentral.contrib.wsone.api_client import Client
from zentral.contrib.wsone.models import Instance
from zentral.contrib.wsone.tasks import do_sync_inventory


logger = logging.getLogger("zentral.contrib.wsone.management.commands.wsone_sync")


class Command(BaseCommand):
    help = "Synchronize inventory"

    def add_arguments(self, parser):
        parser.add_argument('--list-instances', action='store_true', dest='list_instances', default=False,
                            help='list Workspace ONE instances')
        parser.add_argument('--instance', dest='instance_pk', type=int,
                            help='Workspace ONE instance ID')

    def handle(self, *args, **kwargs):
        if kwargs.get("list_instances"):
            for instance in Instance.objects.all().order_by("server_url"):
                print("ID:", instance.pk, "URL:", instance.server_url)
        instance_pk = kwargs.get("instance_pk")
        if not instance_pk:
            return
        try:
            instance = Instance.objects.get(pk=instance_pk)
        except Instance.DoesNotExist:
            raise CommandError(f"Workspace ONE instance {instance_pk} does not exist")
        client = Client.from_instance(instance)
        result = do_sync_inventory(instance, client)
        for key, val in result.items():
            print(f"{key}: {val}")

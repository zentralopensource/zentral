import logging
from django.core.management.base import BaseCommand
from zentral.utils.provisioning import provision


logger = logging.getLogger("zentral.server.base.management.commands.provision")


class Command(BaseCommand):
    help = 'Provision Zentral'

    def handle(self, *args, **options):
        provision()

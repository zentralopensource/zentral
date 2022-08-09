from django.core.management.base import BaseCommand
from zentral.contrib.mdm.software_updates import sync_software_updates


class Command(BaseCommand):
    help = 'Sync software updates'

    def handle(self, *args, **kwargs):
        sync_software_updates()

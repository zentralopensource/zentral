import logging
from django.core.files.storage import default_storage
from django.core.management.base import BaseCommand
from zentral.contrib.inventory.utils import do_full_export
from zentral.utils.storage import file_storage_has_signed_urls


logger = logging.getLogger("zentral.contrib.inventory.management.commands.export_full_inventory")


class Command(BaseCommand):
    help = "Export full inventory as a ZIP archive of .ndjson files"

    def handle(self, *args, **kwargs):
        result = do_full_export()
        filepath = result["filepath"]
        if file_storage_has_signed_urls(default_storage):
            url = default_storage.url(filepath)
            self.stdout.write(f"Download URL: {url}")
        else:
            self.stdout.write(f"File: {filepath}")

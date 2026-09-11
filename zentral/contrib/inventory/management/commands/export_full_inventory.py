import logging
from django.core.files.storage import default_storage
from django.core.management.base import BaseCommand
from zentral.contrib.inventory.utils import FULL_EXPORT_TABLE_NAMES, do_full_export
from zentral.utils.storage import file_storage_has_signed_urls


logger = logging.getLogger("zentral.contrib.inventory.management.commands.export_full_inventory")


class Command(BaseCommand):
    help = "Export the full inventory as a ZIP archive of .jsonl files"

    def add_arguments(self, parser):
        parser.add_argument("--table", action="append", dest="tables", metavar="TABLE",
                            choices=FULL_EXPORT_TABLE_NAMES,
                            help="Export this table only. Repeat the option to export more than one table. "
                                 "Without the option, all the tables are exported.")

    def handle(self, *args, **kwargs):
        result = do_full_export(tables=kwargs["tables"])
        filepath = result["filepath"]
        if file_storage_has_signed_urls(default_storage):
            url = default_storage.url(filepath)
            self.stdout.write(f"Download URL: {url}")
        else:
            self.stdout.write(f"File: {filepath}")

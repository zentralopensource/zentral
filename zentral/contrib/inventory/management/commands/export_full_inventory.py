import logging
from django.core.files.storage import default_storage
from django.core.management.base import BaseCommand
from zentral.contrib.inventory.utils import FULL_EXPORT_FORMATS, FULL_EXPORT_TABLE_NAMES, do_full_export
from zentral.utils.storage import file_storage_has_signed_urls


logger = logging.getLogger("zentral.contrib.inventory.management.commands.export_full_inventory")


class Command(BaseCommand):
    help = "Export the full inventory, as a ZIP archive of .jsonl files, or as Parquet files"

    def add_arguments(self, parser):
        parser.add_argument("--format", dest="export_format", choices=FULL_EXPORT_FORMATS, default="JSONL",
                            help="The format of the export. JSONL by default.")
        parser.add_argument("--table", action="append", dest="tables", metavar="TABLE",
                            choices=FULL_EXPORT_TABLE_NAMES,
                            help="Export this table only. Repeat the option to export more than one table. "
                                 "Without the option, all the tables are exported.")

    def write_object(self, name, label, url_label):
        if file_storage_has_signed_urls(default_storage):
            self.stdout.write(f"{url_label}: {default_storage.url(name)}")
        else:
            self.stdout.write(f"{label}: {name}")

    def handle(self, *args, **kwargs):
        result = do_full_export(tables=kwargs["tables"], export_format=kwargs["export_format"])
        filepath = result.get("filepath")
        if filepath:
            self.write_object(filepath, "File", "Download URL")
        else:
            manifest = result["manifest"]
            location = manifest["location"]
            self.write_object(f"{location}manifest.json", "Manifest", "Manifest URL")
            for key in manifest["files"]:
                self.write_object(f"{location}{key}", "File", "Download URL")

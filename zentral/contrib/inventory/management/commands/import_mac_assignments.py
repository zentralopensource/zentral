import csv
import logging
from django.core.management.base import BaseCommand
import requests
from tqdm import tqdm
from zentral.contrib.inventory.models import MACAddressBlockAssignment
from base.utils import deployment_info

logger = logging.getLogger("zentral.contrib.inventory.management.commands.import_mac_assignments")


class Command(BaseCommand):
    help = "Import MAC assignment blocks"
    sources = ["https://standards-oui.ieee.org/oui/oui.csv",
               "https://standards-oui.ieee.org/oui28/mam.csv",
               "https://standards-oui.ieee.org/oui36/oui36.csv"]

    def add_arguments(self, parser):
        parser.add_argument('--update', action='store_true', dest='update', default=False, help='force update')

    def set_options(self, **options):
        self.update = options["update"]
        self.verbosity = options["verbosity"]

    def write_to_stderr(self, msg):
        if self.verbosity:
            self.stdout.write(msg)

    def handle(self, *args, **kwargs):
        self.set_options(**kwargs)
        if not self.update:
            assignment_count = MACAddressBlockAssignment.objects.all().count()
            if assignment_count > 0:
                self.write_to_stderr("Found {} MAC assignments. Use --update to update.".format(assignment_count))
                return
        headers = {"User-Agent": deployment_info.user_agent}
        for url in self.sources:
            self.write_to_stderr("Import {}".format(url))
            r = requests.get(url, headers=headers)
            if not r.ok:
                logger.error("Could not download file at %s", url)
                continue
            lines = r.text.splitlines()
            skip_headers = True
            if self.verbosity:
                row_iterator = tqdm(csv.reader(lines), total=len(lines))
            else:
                row_iterator = csv.reader(lines)
            for row in row_iterator:
                if skip_headers:
                    skip_headers = False
                    continue
                attrs = [a.strip() for a in row]
                if len(attrs) != 4:
                    logger.error("Invalid row with %s columns", len(attrs))
                else:
                    MACAddressBlockAssignment.objects.import_assignment(*attrs)

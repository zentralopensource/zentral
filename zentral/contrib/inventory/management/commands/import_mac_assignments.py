import csv
import logging
from django.core.management.base import BaseCommand
import requests
from tqdm import tqdm
from zentral.contrib.inventory.models import MACAddressBlockAssignment

logger = logging.getLogger("zentral.contrib.inventory.management.commandes.import_mac_assignments")


class Command(BaseCommand):
    help = "Import MAC assignment blocks"
    sources = ["https://standards.ieee.org/develop/regauth/oui/oui.csv",
               "https://standards.ieee.org/develop/regauth/oui28/mam.csv",
               "https://standards.ieee.org/develop/regauth/oui36/oui36.csv"]

    def add_arguments(self, parser):
        parser.add_argument('--update', action='store_true', dest='update', default=False, help='force update')

    def handle(self, *args, **kwargs):
        if not kwargs['update']:
            assignment_count = MACAddressBlockAssignment.objects.all().count()
            if assignment_count > 0:
                print("Found {} MAC assignments. Use --update to update.".format(assignment_count))
                return
        for url in self.sources:
            print("Import {}".format(url))
            r = requests.get(url)
            if not r.ok:
                logger.error("Could not download file at %s", url)
                continue
            lines = r.text.splitlines()
            skip_headers = True
            for row in tqdm(csv.reader(lines), total=len(lines)):
                if skip_headers:
                    skip_headers = False
                    continue
                args = [a.strip() for a in row]
                MACAddressBlockAssignment.objects.import_assignment(*args)

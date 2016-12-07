import logging
from django.core.management.base import BaseCommand
from django.utils import timezone
from zentral.core.probes.conf import ProbeList
from zentral.core.probes.feeds import export_feed

logger = logging.getLogger("zentral.core.probes.management."
                           "commands.add_probe_feed")


class Command(BaseCommand):
    help = 'Export probes as feed'

    def add_arguments(self, parser):
        parser.add_argument('output_file', type=str, nargs=1)

    def handle(self, **options):
        feed_name = "Export {}".format(timezone.now().strftime("%Y-%m-%d %H:%M:%S"))
        with open(options["output_file"][0], "w", encoding="utf-8") as f:
            f.write(export_feed(feed_name, ProbeList()))

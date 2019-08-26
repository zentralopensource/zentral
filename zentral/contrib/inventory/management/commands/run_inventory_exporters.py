import logging
from django.core.management.base import BaseCommand, CommandError
from zentral.contrib.inventory.exporters import exporters

logger = logging.getLogger("zentral.contrib.inventory.management.commands.run_inventory_exporters")


class Command(BaseCommand):
    help = "Run inventory exporters"

    def add_arguments(self, parser):
        parser.add_argument('--list-exporters', action='store_true', dest='list_exporters', default=False,
                            help='list exporters')
        parser.add_argument('--exporter', dest='exporter_id', type=int, nargs=1,
                            help='run exporter')

    def handle(self, *args, **kwargs):
        if kwargs.get("list_exporters"):
            print("Configured exporters:")
            for idx, exporter in enumerate(exporters):
                print(idx, exporter.name)
                for key, val in exporter.config_d.items():
                    print(key, val)
            return
        exporter_list = exporters
        exporter_id = kwargs.get("exporter_id")
        if exporter_id:
            exporter_id = exporter_id[0]
            try:
                exporter_list = [exporters[exporter_id]]
            except IndexError:
                raise CommandError("Exporter {} does not exist".format(exporter_id))
        for exporter in exporter_list:
            exporter.run()

import logging
from django.core.management.base import BaseCommand
from django.db import connection
from zentral.contrib.inventory.cleanup import cleanup_inventory, get_default_snapshot_retention_days, get_min_date


logger = logging.getLogger("zentral.contrib.inventory.management.commands.cleanup_inventory_history")


class Command(BaseCommand):
    help = "Cleanup inventory history"

    def add_arguments(self, parser):
        parser.add_argument("-q", "--quiet", action="store_true", help="no output if no errors")
        default_snapshot_retention_days = get_default_snapshot_retention_days()
        parser.add_argument(
            '--days', type=int,
            default=default_snapshot_retention_days,
            help=f'number of days to keep, default {default_snapshot_retention_days}'
        )

    def set_options(self, **options):
        self.quiet = options["quiet"] or options["verbosity"] == 0
        self.min_date = get_min_date(options["days"])
        if not self.quiet:
            self.stdout.write("min date: {}".format(self.min_date.isoformat()))

    def handle(self, *args, **kwargs):
        self.set_options(**kwargs)
        with connection.cursor() as cursor:
            cleanup_inventory(cursor, self.result_callback, self.min_date)

    def result_callback(self, table, result):
        if self.quiet:
            return
        if result["status"] == 0:
            self.stdout.write("{}: {} - {:.2f}ms".format(table, result["rowcount"], result["duration"] * 1000))
        else:
            self.stderr.write(f"Could not cleanup table {table}")

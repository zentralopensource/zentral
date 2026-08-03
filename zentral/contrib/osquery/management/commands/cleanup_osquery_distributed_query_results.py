import logging
from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError

from zentral.contrib.osquery.distributed_query_result_stores import get_distributed_query_result_store
from zentral.utils.time import naive_utcnow

logger = logging.getLogger(
    "zentral.contrib.osquery.management.commands.cleanup_osquery_distributed_query_results"
)


class Command(BaseCommand):
    help = "Cleanup the expired osquery distributed query results"

    def add_arguments(self, parser):
        parser.add_argument("-q", "--quiet", action="store_true", help="no output if no errors")
        parser.add_argument(
            "--days", type=int,
            help="number of days to keep, defaults to the distributed_query_results_ttl_days app setting"
        )

    def handle(self, *args, **options):
        quiet = options["quiet"] or options["verbosity"] == 0
        store = get_distributed_query_result_store()
        days = options.get("days") or store.ttl_days
        if not days or days < 1:
            raise CommandError("No number of days to keep")
        cutoff = naive_utcnow() - timedelta(days=days)
        if not quiet:
            self.stdout.write(f"cutoff: {cutoff.isoformat()}")
        deleted = store.delete_expired_results(cutoff)
        if not quiet:
            if deleted is None:
                self.stdout.write("results deletion submitted")
            else:
                self.stdout.write(f"{deleted} result{'' if deleted == 1 else 's'} deleted")

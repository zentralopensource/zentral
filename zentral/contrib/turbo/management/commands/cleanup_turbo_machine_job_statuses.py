import logging
from datetime import timedelta
from django.core.management.base import BaseCommand
from django.db.models import Q
from django.utils import timezone
from zentral.contrib.turbo.models import MachineJobStatus

logger = logging.getLogger(
    "zentral.contrib.turbo.management.commands.cleanup_turbo_machine_job_statuses")

DEFAULT_DAYS = 30


class Command(BaseCommand):
    help = "Purge MachineJobStatus rows the agent stopped reporting long enough ago"

    def add_arguments(self, parser):
        parser.add_argument("-q", "--quiet", action="store_true", help="no output if no errors")
        parser.add_argument(
            "--days", type=int, default=DEFAULT_DAYS,
            help=f"purge rows removed more than this many days ago, default {DEFAULT_DAYS}")

    def handle(self, *args, **options):
        quiet = options["quiet"] or options["verbosity"] == 0
        now = timezone.now()
        cutoff = now - timedelta(days=options["days"])
        # never drop a live one-time gate. not_after is nullable, so we do NOT assume one-time jobs
        # always have one: a row is purged only if it is recurring (no gate), its OneTimeJob window has
        # explicitly closed (not_after set AND in the past), or the job already ran (last_result_at set,
        # so the config no longer serves it). An open-ended one-time job (not_after NULL) that has NOT
        # yet run is still serveable, so it is kept.
        deleted, _ = (
            MachineJobStatus.objects
            .filter(removed_at__lt=cutoff)
            .filter(Q(one_time_job__isnull=True)
                    | Q(one_time_job__not_after__lt=now)
                    | Q(last_result_at__isnull=False))
            .delete()
        )
        if not quiet:
            self.stdout.write(f"Purged {deleted} Turbo machine job status(es)")

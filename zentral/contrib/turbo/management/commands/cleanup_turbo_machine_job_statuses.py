import logging
from datetime import timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
from zentral.contrib.turbo.models import OneTimeJobMachine, RecurringJobMachine

logger = logging.getLogger(
    "zentral.contrib.turbo.management.commands.cleanup_turbo_machine_job_statuses")

DEFAULT_DAYS = 30


class Command(BaseCommand):
    help = "Purge Turbo per-machine tracker rows the agent stopped reporting long enough ago"

    def add_arguments(self, parser):
        parser.add_argument("-q", "--quiet", action="store_true", help="no output if no errors")
        parser.add_argument(
            "--days", type=int, default=DEFAULT_DAYS,
            help=f"purge rows removed more than this many days ago, default {DEFAULT_DAYS}")

    def handle(self, *args, **options):
        quiet = options["quiet"] or options["verbosity"] == 0
        now = timezone.now()
        cutoff = now - timedelta(days=options["days"])
        # recurring trackers gate nothing (recurring jobs are always served), so a stale removed row can
        # always go.
        recurring_deleted, _ = (
            RecurringJobMachine.objects.filter(removed_at__lt=cutoff).delete()
        )
        # never drop a live one-time gate: while the OneTimeJob window is open, the row itself —
        # last_result_at included — is what stops the config endpoint from re-serving (and the agent from
        # re-running) the job, done or not. So a one-time tracker is purged only once its window has
        # explicitly closed (not_after set AND in the past). not_after is nullable: open-ended one-time
        # rows are kept forever (bounded by machine count).
        one_time_deleted, _ = (
            OneTimeJobMachine.objects
            .filter(removed_at__lt=cutoff, one_time_job__not_after__lt=now)
            .delete()
        )
        if not quiet:
            self.stdout.write(
                f"Purged {recurring_deleted + one_time_deleted} Turbo machine tracker(s)")

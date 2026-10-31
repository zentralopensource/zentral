from datetime import timedelta
from django.core.management.base import BaseCommand
from zentral.contrib.mdm.events import (post_status_report_cleanup_finished_event,
                                        post_status_report_cleanup_started_event)
from zentral.contrib.mdm.status_reports import cleanup_status_reports, get_default_status_report_retention_days
from zentral.core.queues import queues
from zentral.utils.time import naive_utcnow


class Command(BaseCommand):
    help = "Delete the DDM status reports older than the retention, except the ones the status is rebuilt from"

    def add_arguments(self, parser):
        parser.add_argument("-q", "--quiet", action="store_true", help="no output if no errors")
        default_retention_days = get_default_status_report_retention_days()
        parser.add_argument(
            "--days", type=int,
            default=default_retention_days,
            help=f"number of days to keep, default {default_retention_days}"
        )

    def handle(self, *args, **options):
        quiet = options["quiet"] or options["verbosity"] == 0
        days = max(1, options["days"])
        max_date = naive_utcnow() - timedelta(days=days)
        payload = {"days": days, "max_date": max_date.isoformat()}
        post_status_report_cleanup_started_event(payload.copy())
        payload["tables"] = {}

        def result_callback(table, result):
            payload["tables"][table] = result
            if not quiet:
                self.stdout.write(f"{table}: {result['rowcount']} deleted, "
                                  f"max {result['max_rows_per_target']} per target - "
                                  f"{result['duration'] * 1000:.2f}ms")

        payload["duration"] = cleanup_status_reports(max_date, result_callback)
        post_status_report_cleanup_finished_event(payload)
        queues.stop()

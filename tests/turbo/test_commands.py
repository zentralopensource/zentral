import io
from datetime import timedelta
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone
from django.utils.crypto import get_random_string
from zentral.contrib.turbo.models import MachineJobStatus
from .utils import force_configuration, force_one_time_job, force_recurring_job


class TurboCleanupCommandTestCase(TestCase):
    def test_cleanup_machine_job_statuses(self):
        configuration = force_configuration()
        serial_number = get_random_string(12)
        old = timezone.now() - timedelta(days=40)
        recent = timezone.now() - timedelta(days=10)

        def recurring(removed_at):
            return MachineJobStatus.objects.create(
                serial_number=serial_number, job=force_recurring_job(configuration=configuration).job,
                removed_at=removed_at)

        def one_time(removed_at, not_after, last_result_at=None):
            otj = force_one_time_job(configuration=configuration, not_after=not_after)
            return MachineJobStatus.objects.create(
                serial_number=serial_number, job=otj.job, one_time_job=otj, removed_at=removed_at,
                last_result_at=last_result_at)

        recurring_old = recurring(old)            # removed long ago → purged
        recurring_recent = recurring(recent)      # removed recently → kept
        recurring_live = recurring(None)          # still held → kept
        one_time_expired = one_time(old, timezone.now() - timedelta(days=1))   # window closed → purged
        one_time_open = one_time(old, None)       # open-ended, never ran → kept (live gate)
        # open-ended but already ran: config no longer serves it, so the dead gate is purged
        one_time_done_open = one_time(old, None, last_result_at=old)

        call_command("cleanup_turbo_machine_job_statuses", "--quiet")

        remaining = set(MachineJobStatus.objects.values_list("pk", flat=True))
        self.assertNotIn(recurring_old.pk, remaining)
        self.assertIn(recurring_recent.pk, remaining)
        self.assertIn(recurring_live.pk, remaining)
        self.assertNotIn(one_time_expired.pk, remaining)
        self.assertIn(one_time_open.pk, remaining)
        self.assertNotIn(one_time_done_open.pk, remaining)

    def test_cleanup_command_output(self):
        out = io.StringIO()
        call_command("cleanup_turbo_machine_job_statuses", stdout=out)
        self.assertIn("Purged", out.getvalue())

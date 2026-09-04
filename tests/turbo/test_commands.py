import io
import threading
import uuid
from datetime import timedelta
from unittest.mock import patch
from django.core.management import call_command
from django.db import connection, transaction
from django.test import TestCase, TransactionTestCase
from django.utils import timezone
from django.utils.crypto import get_random_string
from zentral.contrib.turbo.models import (JobUpload, OneTimeJobMachine, RecurringJobMachine, UploadMode,
                                          UploadStatus, UploadVerification)
from .utils import force_configuration, force_one_time_job, force_recurring_job


class TurboCleanupCommandTestCase(TestCase):
    def test_cleanup_machine_trackers(self):
        configuration = force_configuration()
        serial_number = get_random_string(12)
        old = timezone.now() - timedelta(days=40)
        recent = timezone.now() - timedelta(days=10)

        def recurring(removed_at):
            return RecurringJobMachine.objects.create(
                serial_number=serial_number, recurring_job=force_recurring_job(configuration=configuration),
                removed_at=removed_at)

        def one_time(removed_at, not_after, last_result_at=None):
            otj = force_one_time_job(configuration=configuration, not_after=not_after)
            return OneTimeJobMachine.objects.create(
                serial_number=serial_number, one_time_job=otj, removed_at=removed_at,
                last_result_at=last_result_at)

        recurring_old = recurring(old)            # removed long ago → purged (recurring gates nothing)
        recurring_recent = recurring(recent)      # removed recently → kept
        recurring_live = recurring(None)          # still held → kept
        one_time_expired = one_time(old, timezone.now() - timedelta(days=1))   # window closed → purged
        one_time_open = one_time(old, None)       # open-ended, never ran → kept (live gate)
        # open-ended and already ran: the row IS what stops the config from re-serving the job, so
        # purging it would make the agent run the one-time job again → kept (live gate)
        one_time_done_open = one_time(old, None, last_result_at=old)
        # already ran AND window closed: the window alone stops re-serving → purged
        one_time_done_expired = one_time(old, timezone.now() - timedelta(days=1), last_result_at=old)

        call_command("cleanup_turbo_machine_job_statuses", "--quiet")

        # int pks are per-table, so check each table's survivors separately
        recurring_remaining = set(RecurringJobMachine.objects.values_list("pk", flat=True))
        one_time_remaining = set(OneTimeJobMachine.objects.values_list("pk", flat=True))
        self.assertNotIn(recurring_old.pk, recurring_remaining)
        self.assertIn(recurring_recent.pk, recurring_remaining)
        self.assertIn(recurring_live.pk, recurring_remaining)
        self.assertNotIn(one_time_expired.pk, one_time_remaining)
        self.assertIn(one_time_open.pk, one_time_remaining)
        self.assertIn(one_time_done_open.pk, one_time_remaining)
        self.assertNotIn(one_time_done_expired.pk, one_time_remaining)

    def test_cleanup_command_output(self):
        out = io.StringIO()
        call_command("cleanup_turbo_machine_job_statuses", stdout=out)
        self.assertIn("Purged", out.getvalue())


def force_owed_upload(minutes_ago=120, **overrides):
    # a multipart upload: the result arrived `minutes_ago` minutes ago, and the verification is pending
    attributes = {"schedule_pk": uuid.uuid4(), "schedule_mode": "one_time",
                  "serial_number": get_random_string(12), "run_id": uuid.uuid4(), "artifact": "archive",
                  "key": "turbo/uploads/test/archive.tar.gz", "size": 200, "sha256": "a" * 64,
                  "crc64nvme": "9c3fa1075ed248b1", "mode": UploadMode.MULTIPART, "upload_id": "mpu-1",
                  "part_size": 100, "status": UploadStatus.UPLOADED,
                  "completed_at": timezone.now() - timedelta(minutes=minutes_ago)}
    attributes.update(overrides)
    return JobUpload.objects.create(**attributes)


@patch("zentral.contrib.turbo.management.commands.sweep_turbo_uploads.complete_multipart_upload_task")
class TurboSweepUploadsCommandTestCase(TestCase):
    """The sweep asks again for the pending completions, because the completion task makes no retries."""

    def _sweep(self, *args, **kwargs):
        with self.captureOnCommitCallbacks(execute=True):
            call_command("sweep_turbo_uploads", *args, **kwargs)

    def test_only_the_completions_still_owed_are_asked_again(self, task):
        owed = force_owed_upload()
        # a recent result: the completion task of the ingest can still run
        force_owed_upload(minutes_ago=10)
        # a decided verification is final
        force_owed_upload(verification=UploadVerification.VERIFIED)
        force_owed_upload(verification=UploadVerification.ASSEMBLY_FAILED)
        # no result: the agent can still upload parts
        force_owed_upload(status=UploadStatus.PENDING, completed_at=None)
        # a failed upload: the abort task deletes its parts
        force_owed_upload(status=UploadStatus.FAILED)
        # a single PUT has no completion
        force_owed_upload(mode=UploadMode.PUT, upload_id=None, part_size=None)
        self._sweep("--quiet")
        task.apply_async.assert_called_once_with((str(owed.pk),))

    def test_an_upload_is_asked_once_in_the_window(self, task):
        # several worker instances run the command: a second run in the window asks for nothing
        owed = force_owed_upload()
        self._sweep("--quiet")
        self._sweep("--quiet")
        task.apply_async.assert_called_once_with((str(owed.pk),))
        owed.refresh_from_db()
        self.assertIsNotNone(owed.last_swept_at)

    def test_once_the_window_closes_the_sweep_asks_again(self, task):
        owed = force_owed_upload(last_swept_at=timezone.now() - timedelta(minutes=90))
        self._sweep("--quiet")
        task.apply_async.assert_called_once_with((str(owed.pk),))

    def test_an_hourly_cron_asks_again_on_every_run(self, task):
        # this hourly run starts one second early. The default window is shorter than the interval, so this run asks
        # again.
        owed = force_owed_upload(last_swept_at=timezone.now() - timedelta(minutes=59, seconds=59))
        self._sweep("--quiet")
        task.apply_async.assert_called_once_with((str(owed.pk),))

    def test_a_completion_that_can_still_run_is_not_asked_again(self, task):
        # asked 30 minutes ago, the longest completion: the task can still run
        force_owed_upload(last_swept_at=timezone.now() - timedelta(minutes=30))
        self._sweep("--quiet")
        task.apply_async.assert_not_called()

    def test_the_min_age_is_an_option(self, task):
        recent = force_owed_upload(minutes_ago=10)
        self._sweep("--quiet", "--min-age", "5")
        task.apply_async.assert_called_once_with((str(recent.pk),))

    def test_output(self, task):
        force_owed_upload()
        out = io.StringIO()
        self._sweep(stdout=out)
        self.assertEqual(out.getvalue(), "Asked again for 1 Turbo multipart upload completion(s)\n")


class TurboSweepUploadsOverlapTestCase(TransactionTestCase):
    """Two runs at the same time: one claims a row, and the other skips it.

    A TransactionTestCase, because the second run needs its own transaction and its own connection.
    """

    @patch("zentral.contrib.turbo.management.commands.sweep_turbo_uploads.complete_multipart_upload_task")
    def test_a_row_claimed_by_an_overlapping_run_is_skipped(self, task):
        owed = force_owed_upload()
        locked, release = threading.Event(), threading.Event()

        def overlapping_run():
            try:
                with transaction.atomic():
                    JobUpload.objects.select_for_update().get(pk=owed.pk)
                    locked.set()
                    # a time limit: if the sweep waits for the lock, the test fails and does not hang
                    release.wait(5)
            finally:
                connection.close()

        thread = threading.Thread(target=overlapping_run)
        thread.start()
        try:
            self.assertTrue(locked.wait(5))
            call_command("sweep_turbo_uploads", "--quiet")
        finally:
            release.set()
            thread.join()
        task.apply_async.assert_not_called()
        owed.refresh_from_db()
        self.assertIsNone(owed.last_swept_at)

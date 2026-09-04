from datetime import timedelta
from functools import partial
from django.core.management.base import BaseCommand
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from zentral.contrib.turbo.models import JobUpload, UploadMode, UploadStatus, UploadVerification
from zentral.contrib.turbo.tasks import complete_multipart_upload_task

# The window, in minutes.
#
# Longer than 30 minutes, the longest completion task: three attempts with a read timeout of ten minutes.
# A shorter window asks again for a completion that still runs. The task is idempotent, so this is only
# work that is not necessary.
#
# Shorter than the interval of the cron, with a margin. A run sets last_swept_at to its start time, and the
# next run asks again only if last_swept_at is older than the window. With a window equal to the interval,
# a run that starts some milliseconds early does not ask again. 45 minutes gives 15 minutes of margin for
# an hourly cron.
DEFAULT_MIN_AGE = 45


class Command(BaseCommand):
    help = "Ask again for the completion of the Turbo multipart uploads that are still owed one"

    def add_arguments(self, parser):
        parser.add_argument("-q", "--quiet", action="store_true", help="no output if no errors")
        parser.add_argument(
            "--min-age", type=int, default=DEFAULT_MIN_AGE,
            help=("only uploads whose result arrived, and that the sweep did not ask for, at least this "
                  f"many minutes ago, default {DEFAULT_MIN_AGE}. Longer than 30 minutes, the worst case of "
                  "one completion, and shorter than the interval of the cron"))

    def handle(self, *args, **options):
        quiet = options["quiet"] or options["verbosity"] == 0
        now = timezone.now()
        cutoff = now - timedelta(minutes=options["min_age"])
        with transaction.atomic():
            # The result arrived, so all the parts are uploaded, but the verification is still pending: the
            # storage was unavailable, or the enqueue was lost. Without a result, the agent can still upload
            # parts, and a completion now is a final failure.
            #
            # Several worker instances run this command, so two runs can overlap. SKIP LOCKED gives
            # different rows to two overlapping runs, and last_swept_at prevents a second request in the
            # window. Like notification_queued_at in the APNS worker, this needs no lock and no selected
            # instance.
            upload_pks = list(
                JobUpload.objects.select_for_update(skip_locked=True)
                .filter(mode=UploadMode.MULTIPART, status=UploadStatus.UPLOADED,
                        verification=UploadVerification.PENDING, completed_at__lt=cutoff)
                .filter(Q(last_swept_at__isnull=True) | Q(last_swept_at__lt=cutoff))
                .exclude(upload_id__isnull=True).exclude(upload_id="")
                .values_list("pk", flat=True)
            )
            JobUpload.objects.filter(pk__in=upload_pks).update(last_swept_at=now)
            for upload_pk in upload_pks:
                # after the commit of the claim
                transaction.on_commit(partial(complete_multipart_upload_task.apply_async, (str(upload_pk),)))
        if not quiet:
            self.stdout.write(f"Asked again for {len(upload_pks)} Turbo multipart upload completion(s)")

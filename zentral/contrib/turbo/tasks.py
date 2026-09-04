import logging

from celery import shared_task
from django.core.files.storage import storages
from django.utils import timezone

from zentral.utils.storage import (abort_multipart_upload, complete_multipart_upload,
                                   list_multipart_parts, stat_object)

from .models import JobUpload, UploadMode, UploadStatus, UploadVerification

logger = logging.getLogger("zentral.contrib.turbo.tasks")


# What the storage says when the upload cannot be assembled, ever. A checksum that does not match the
# bytes, or a part list that cannot make an object — none of it improves by asking again, and a retry
# would only keep the parts alive and billed. Everything else is transient by default: a storage that
# is unreachable or throttling gets the backoff.
TERMINAL_COMPLETION_ERRORS = {
    "BadDigest",              # the whole-object checksum the agent declared is not what arrived
    "EntityTooSmall",         # a part below the minimum, so the geometry never made an object
    "InvalidPart",            # a part the storage does not have, or whose ETag moved
    "InvalidPartOrder",
    "InvalidRequest",
}


@shared_task(bind=True, max_retries=5)
def complete_multipart_upload_task(self, upload_pk):
    """Assemble a multipart upload, and record on the row whether the storage agreed.

    This is the second axis for a multipart object, and the only place it is decided: the whole-object
    checksum is validated by the completion itself, so there is nothing left for the ingest to HEAD.

    Idempotent by design, because the agent may call the endpoint again after a timeout and the result
    ingest re-enqueues any upload still waiting on one. Completing an upload that is already complete
    is success, not an error.
    """
    from botocore.exceptions import ClientError

    upload = JobUpload.objects.get(pk=upload_pk)
    result = {"upload": {"pk": str(upload.pk), "key": upload.key}}
    if upload.mode != UploadMode.MULTIPART or not upload.upload_id:
        # nothing to assemble. Reachable through a re-enqueue that raced a row it does not describe.
        logger.error("Turbo upload %s is not a multipart upload", upload.pk)
        return {**result, "status": "not_multipart"}
    if upload.verification == UploadVerification.VERIFIED:
        return {**result, "status": "already_verified"}

    storage = storages["default"]
    try:
        parts = list_multipart_parts(upload.key, upload.upload_id, storage=storage)
    except ClientError as error:
        return _settle(self, upload, result, error, storage)
    if not parts:
        # the agent said every part was up and the storage is holding none: either they aged out on
        # the AbortIncompleteMultipartUpload rule, or they were never there. Nothing to wait for.
        return _record(upload, {**result, "status": "no_parts"}, UploadVerification.ASSEMBLY_FAILED)

    result["parts"] = len(parts)
    try:
        complete_multipart_upload(upload.key, upload.upload_id, parts, upload.crc64nvme, upload.size,
                                  storage=storage)
    except ClientError as error:
        return _settle(self, upload, result, error, storage)
    return _record(upload, {**result, "status": "completed"}, UploadVerification.VERIFIED)


def _settle(task, upload, result, error, storage):
    """What a failed storage call means: done already, done for, or worth another try."""
    code = error.response.get("Error", {}).get("Code", "")
    if code == "NoSuchUpload":
        # the upload id is gone, which is what the storage says BOTH for one that completed already
        # and for one whose parts were aborted. The object itself is the only thing that tells them
        # apart, and a second completion call is exactly how the first case arrives here.
        try:
            stored = stat_object(upload.key, storage=storage)
        except Exception:
            logger.exception("Could not stat turbo upload %s", upload.pk)
            raise task.retry(exc=error, countdown=60 * 2 ** task.request.retries)
        if _is_the_completed_object(stored, upload):
            return _record(upload, {**result, "status": "already_completed"},
                           UploadVerification.VERIFIED)
        return _record(upload, {**result, "status": "parts_gone"},
                       UploadVerification.ASSEMBLY_FAILED)
    if code in TERMINAL_COMPLETION_ERRORS:
        logger.error("Turbo upload %s could not be assembled: %s", upload.pk, code)
        return _record(upload, {**result, "status": "failed", "error": code},
                       UploadVerification.ASSEMBLY_FAILED)
    raise task.retry(exc=error, countdown=60 * 2 ** task.request.retries)


def _is_the_completed_object(stored, upload):
    # is the object at the key this upload, assembled? The CRC settles it: the HEAD reports the
    # whole-object value the completion validated, and the row holds the one the agent declared, so a
    # match is exact where a match on the size alone can be a coincidence. The size is the fallback
    # for an object whose checksum the HEAD does not carry.
    if stored is None:
        return False
    if stored["crc64nvme"] and upload.crc64nvme:
        return stored["crc64nvme"] == upload.crc64nvme
    return stored["size"] == upload.size


def _record(upload, result, verification):
    # the verification axis only, and update_fields so it is only that. This row was loaded before
    # ListParts and CompleteMultipartUpload, which the storages document as taking MINUTES, and the
    # result for the same run arrives in that window and closes the status axis. A full save here
    # would write this stale copy back over it: the status would return to pending for good — the
    # agent has been acknowledged and never resends — the row would count against MAX_PENDING_UPLOADS,
    # and the console would show a report that did arrive as one that did not.
    upload.verification = verification
    upload.verified_at = timezone.now()
    upload.save(update_fields=["verification", "verified_at", "updated_at"])
    return {**result, "verification": verification}


@shared_task
def abort_multipart_upload_task(upload_pk):
    """Drop the parts of an upload the agent has given up on.

    The bucket's AbortIncompleteMultipartUpload rule is the backstop, and it has to be: a result can
    be a day behind, so it is often the first thing to act. This is the fast path for the case where
    the agent told us, so the parts stop being billed today rather than at the end of that window.
    """
    from botocore.exceptions import ClientError

    upload = JobUpload.objects.get(pk=upload_pk)
    if upload.mode != UploadMode.MULTIPART or not upload.upload_id:
        return {"status": "not_multipart"}
    if upload.status != UploadStatus.FAILED:
        # the row moved on between the enqueue and here — an abort now would drop the parts of an
        # upload somebody is still counting on
        return {"status": "not_failed"}
    try:
        abort_multipart_upload(upload.key, upload.upload_id, storage=storages["default"])
    except ClientError as error:
        if error.response.get("Error", {}).get("Code", "") != "NoSuchUpload":
            raise
        # already gone, which is the outcome we wanted
    return {"upload": {"pk": str(upload.pk), "key": upload.key}, "status": "aborted"}

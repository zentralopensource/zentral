import logging

from celery import shared_task
from django.core.files.storage import storages
from django.utils import timezone

from zentral.utils.storage import (MultipartUploadNotFound, MultipartUploadRefused, StorageError,
                                   StorageUnavailable, abort_multipart_upload, complete_multipart_upload,
                                   list_multipart_parts, stat_object)

from .models import JobUpload, UploadMode, UploadStatus, UploadVerification
from .uploads import part_lengths

logger = logging.getLogger("zentral.contrib.turbo.tasks")


@shared_task
def complete_multipart_upload_task(upload_pk):
    """Assemble a multipart upload, and record the verification on the row.

    The completion validates the whole-object checksum, so this is the only verification of a multipart
    upload. The task is idempotent: the agent, the result ingest and the sweep_turbo_uploads command can
    enqueue it again. An upload that is already complete is a success.

    No retries. After an outage, the upload stays pending, and the sweep asks again.
    """
    upload = JobUpload.objects.get(pk=upload_pk)
    result = {"upload": {"pk": str(upload.pk), "key": upload.key}}
    if upload.mode != UploadMode.MULTIPART or not upload.upload_id:
        logger.error("Turbo upload %s is not a multipart upload", upload.pk)
        return {**result, "status": "not_multipart"}
    if upload.verification != UploadVerification.PENDING:
        # a decided verification is final
        return {**result, "status": "already_decided", "verification": upload.verification}

    storage = storages["default"]
    try:
        parts = list_multipart_parts(upload.key, upload.upload_id, storage=storage)
        if not parts:
            # the agent said that all the parts are uploaded, but the storage has none: a bucket rule
            # deleted them, or the agent did not upload them
            return _record(upload, {**result, "status": "no_parts"}, UploadVerification.ASSEMBLY_FAILED)
        result["parts"] = len(parts)
        if upload.part_size:
            # the completion gives only the error of the storage. The geometry of the row gives the numbers of the
            # missing parts.
            expected = len(part_lengths(upload.size, upload.part_size))
            missing = sorted(set(range(1, expected + 1)) - {part["PartNumber"] for part in parts})
            if missing:
                logger.error("Turbo upload %s is missing parts %s", upload.pk, missing)
                return _record(upload, {**result, "status": "missing_parts", "missing": missing},
                               UploadVerification.ASSEMBLY_FAILED)
        complete_multipart_upload(upload.key, upload.upload_id, parts, upload.crc64nvme, upload.size,
                                  storage=storage)
    except MultipartUploadNotFound:
        return _completed_or_gone(upload, result, storage)
    except MultipartUploadRefused as error:
        logger.error("Turbo upload %s could not be assembled: %s", upload.pk, error)
        return _record(upload, {**result, "status": "failed", "error": str(error)},
                       UploadVerification.ASSEMBLY_FAILED)
    except StorageError as error:
        return _postponed(upload, result, error)
    return _record(upload, {**result, "status": "completed"}, UploadVerification.VERIFIED)


def _completed_or_gone(upload, result, storage):
    # The storage has no upload with this id when the upload is complete, and when it is aborted. Only the
    # object shows which. A second completion call gets the first case.
    try:
        stored = stat_object(upload.key, storage=storage)
    except StorageError as error:
        return _postponed(upload, result, error)
    if _is_the_completed_object(stored, upload):
        return _record(upload, {**result, "status": "already_completed"}, UploadVerification.VERIFIED)
    return _record(upload, {**result, "status": "parts_gone"}, UploadVerification.ASSEMBLY_FAILED)


def _postponed(upload, result, error):
    # The upload stays pending, and the sweep asks again. Only an outage is a warning. A configuration
    # error, for example a bucket policy, stays until somebody corrects it.
    level = logging.WARNING if isinstance(error, StorageUnavailable) else logging.ERROR
    logger.log(level, "Turbo upload %s: completion postponed: %s", upload.pk, error)
    return {**result, "status": "postponed", "error": str(error)}


def _is_the_completed_object(stored, upload):
    # The CRC decides: the storage reports the CRC that the completion validated, and the row has the CRC
    # that the agent declared. The size decides only when the storage reports no CRC.
    if stored is None:
        return False
    stored_crc64nvme = stored["digests"].get("crc64nvme")
    if stored_crc64nvme and upload.crc64nvme:
        return stored_crc64nvme == upload.crc64nvme
    return stored["size"] == upload.size


def _record(upload, result, verification):
    # A conditional update of the verification only. The completion can take minutes, and the result can
    # arrive during that time. A full save writes the old status back: the row stays pending, and counts
    # against MAX_PENDING_UPLOADS. The ingest can also record a mismatch during that time, and the
    # mismatch must stay.
    now = timezone.now()
    recorded = JobUpload.objects.filter(pk=upload.pk, verification=UploadVerification.PENDING).update(
        verification=verification, verified_at=now, updated_at=now)
    if not recorded:
        logger.info("Turbo upload %s: a verdict was already recorded, %s not written", upload.pk, verification)
        return {**result, "verification": verification, "recorded": False}
    return {**result, "verification": verification}


@shared_task
def abort_multipart_upload_task(upload_pk):
    """Delete the parts of an upload that will not complete.

    A bucket rule deletes them after some days. This task deletes them when the result arrives.
    """
    upload = JobUpload.objects.get(pk=upload_pk)
    result = {"upload": {"pk": str(upload.pk), "key": upload.key}}
    if upload.mode != UploadMode.MULTIPART or not upload.upload_id:
        return {"status": "not_multipart"}
    if upload.status != UploadStatus.FAILED and upload.verification != UploadVerification.MISMATCH:
        # the upload can still complete. A mismatch is final, so nothing completes it.
        return {"status": "not_failed"}
    try:
        abort_multipart_upload(upload.key, upload.upload_id, storage=storages["default"])
    except MultipartUploadNotFound:
        # already deleted
        pass
    except StorageError as error:
        # no retry: the bucket rule deletes the parts later
        level = logging.WARNING if isinstance(error, StorageUnavailable) else logging.ERROR
        logger.log(level, "Turbo upload %s: parts not dropped: %s", upload.pk, error)
        return {**result, "status": "not_aborted", "error": str(error)}
    return {**result, "status": "aborted"}

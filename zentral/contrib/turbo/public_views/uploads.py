import hashlib
import logging
import uuid
from datetime import timedelta

from django.core.files.base import ContentFile
from django.core.files.storage import storages
from django.db import transaction
from django.core.exceptions import RequestDataTooBig
from django.http import JsonResponse
from django.utils import timezone
from django.views.generic import View

from zentral.utils.storage import StorageError

from ..models import (JobUpload, ScheduleMode, UploadMode, UploadStatus, UploadVerification,
                      get_machine_schedule, one_time_gate_closed)
from ..tasks import complete_multipart_upload_task
from ..uploads import (MAX_PENDING_UPLOADS, MAX_UPLOAD_ATTEMPTS, UPLOAD_URL_EXPIRY,
                       build_upload_destination, build_upload_key, parse_digests, parse_sha256,
                       part_lengths, start_multipart_upload, unsign_hosted_upload, upload_max_size,
                       upload_mode)
from .base import BaseEnrolledMachinePostView, WireError

logger = logging.getLogger("zentral.contrib.turbo.public_views.uploads")


def _block(data, key):
    # the request is built from the result's own blocks, so an agent keeps one run and one upload
    # value per artifact and sends them unchanged to the mint, the completion and the result
    value = data.get(key)
    if not isinstance(value, dict):
        raise WireError(f"missing_{key}")
    return value


def _uuid(block, key, code):
    value = block.get(key)
    if not isinstance(value, str):
        raise WireError(f"missing_{code}")
    try:
        return uuid.UUID(value)
    except ValueError:
        raise WireError(f"invalid_{code}")


def _run_and_artifact(data):
    """The upload's identity: the result's `run` block, and the `artifact` of its `upload` block."""
    run = _block(data, "run")
    schedule_pk = _uuid(run, "schedule_pk", "schedule_pk")
    # the run identity, and the reason this plane can serve a recurring schedule at all: without
    # it two runs of one schedule are indistinguishable and would share a row
    run_id = _uuid(run, "id", "run_id")
    upload = _block(data, "upload")
    artifact_name = upload.get("artifact")
    if not isinstance(artifact_name, str) or not artifact_name:
        raise WireError("missing_artifact")
    return schedule_pk, run_id, upload, artifact_name


def _part_numbers(value):
    """The part numbers of a resume, or None if the request is not a resume.

    The geometry of the row decides which part numbers exist.
    """
    if value is None:
        return None
    if not isinstance(value, list) or not value:
        raise WireError("invalid_missing_parts")
    numbers = []
    for number in value:
        if not isinstance(number, int) or isinstance(number, bool) or number < 1:
            raise WireError("invalid_missing_parts")
        numbers.append(number)
    return sorted(set(numbers))


class UploadMintView(BaseEnrolledMachinePostView):
    """`POST /public/turbo/uploads/` — where the agent asks for somewhere to put an artifact.

    Just-in-time, and never in the config payload: that payload is a pure function of (definition,
    version), cached and re-served to every in-scope machine, so a URL in it would be expired for the
    machines that needed it most and a live write credential for the ones that did not.
    """
    request_type = "upload"

    def do_post(self, data):
        # {"run": {"id", "schedule_pk"}, "upload": {"artifact", "size", "sha256", "digests"}}: the
        # result's run block, and one of its uploads[] entries without the key, which is ours to build
        schedule_pk, run_id, upload_block, artifact_name = _run_and_artifact(data)
        size = upload_block.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise WireError("invalid_size")
        sha256 = parse_sha256(upload_block.get("sha256"))
        if sha256 is None:
            raise WireError("invalid_sha256")
        digests = parse_digests(upload_block.get("digests"))
        if digests is None:
            raise WireError("invalid_digests")
        # A resume: the parts that need a URL. The agent says that the other parts are in the storage. Not
        # in the upload block, because a result entry does not have it. The run and the artifact identify
        # the row.
        missing_parts = _part_numbers(data.get("missing_parts"))

        resolved = get_machine_schedule(self.configuration, self.serial_number, schedule_pk)
        if resolved is None:
            # unknown, another configuration's, out of scope, or outside its window. The agent
            # abandons silently: a result for it would be skipped as unknown_schedule anyway.
            raise WireError("unknown_schedule", status=404)
        schedule, job = resolved
        if schedule.wire_mode == ScheduleMode.ONE_TIME and one_time_gate_closed(schedule, self.serial_number):
            raise WireError("gate_closed", status=410)

        artifact = job.get_artifact(artifact_name)
        if artifact is None:
            # either the kind produces nothing, or it does not produce this. Terminal for the agent:
            # no retry will make a declaration appear.
            raise WireError("unknown_artifact")

        storage = storages["default"]
        if size > self._max_size(job, storage):
            raise WireError("too_large", status=413)
        self._check_pending(schedule.pk, run_id, artifact_name)

        mode = upload_mode(size, storage)
        if mode == UploadMode.MULTIPART and not digests.get("crc64nvme"):
            # the CRC is the only validation of a multipart object: S3 does not calculate a whole-object
            # SHA-256 of a multipart upload
            raise WireError("missing_digest")

        lookup = {"schedule_pk": schedule.pk, "serial_number": self.serial_number,
                  "run_id": run_id, "artifact": artifact_name}
        if missing_parts is not None:
            # A resume continues a multipart upload, so the row must exist. Do not create it: a new
            # multipart upload with only the missing parts cannot assemble. The refusal comes before a
            # write, so no empty pending row counts against MAX_PENDING_UPLOADS. 409, not 400: the agent
            # asks again without the list, and uploads all the parts.
            upload = (JobUpload.objects.filter(**lookup, mode=UploadMode.MULTIPART, upload_id__isnull=False)
                                       .exclude(upload_id="").first())
            if upload is None:
                raise WireError("no_upload_in_flight", status=409)
            created = False
        else:
            upload, created = JobUpload.objects.get_or_create(
                **lookup,
                defaults={"schedule_mode": schedule.wire_mode, "size": size, "sha256": sha256,
                          "crc64nvme": digests.get("crc64nvme", ""),
                          "crc32c": digests.get("crc32c", ""),
                          "mode": mode,
                          "key": ""},
            )
        # A result closed the row. The run is over for this artifact, so a new URL would write an
        # object that no result can point to. For a one-time job, the gate above is still open when
        # that result came from an older version, so the row itself must refuse.
        if upload.status == UploadStatus.UPLOADED:
            raise WireError("already_uploaded", status=410)
        if upload.mode == UploadMode.MULTIPART and upload.verification != UploadVerification.PENDING:
            # the completion is decided, but the result did not arrive yet: for example, the agent
            # restarted after its complete call. The storage does not have this upload id now.
            raise WireError("already_uploaded", status=410)
        if upload.status == UploadStatus.FAILED:
            raise WireError("already_failed", status=410)
        if upload.attempts >= MAX_UPLOAD_ATTEMPTS:
            raise WireError("attempts_exhausted")
        if not created and (size, sha256) != (upload.size, upload.sha256):
            # One run, one artifact, one set of bytes. Other bytes are another artifact, and need another
            # run. The row keeps the first declaration, so the key, the signature and the verification are
            # for the same file. On a multipart row, the uploaded parts and the geometry are for the first
            # bytes.
            raise WireError("artifact_changed")
        if missing_parts is not None and missing_parts[-1] > len(part_lengths(upload.size, upload.part_size)):
            # the geometry of the row does not have this part: the record of the agent is for another upload
            raise WireError("invalid_missing_parts")

        # a retry re-signs the SAME key, so it overwrites in place instead of leaving a twin
        if not upload.key:
            upload.key = build_upload_key(upload, artifact)
        if upload.mode == UploadMode.MULTIPART and not upload.upload_id:
            try:
                start_multipart_upload(upload, artifact, storage)
            except StorageError:
                # The only storage call of this endpoint. A 503, not an HTML 500: the agent mints again
                # later. If the storage created an upload without an answer, the bucket rule deletes it.
                logger.exception("Turbo upload mint from %s: could not start the multipart upload",
                                 self.serial_number)
                raise WireError("storage_unavailable", status=503)
        upload.attempts += 1
        # named fields: a full save can write an old verification over the one of the completion task
        upload.save(update_fields=["key", "upload_id", "part_size", "attempts", "updated_at"])

        destination = build_upload_destination(upload, artifact, storage, missing_parts)
        self.request_event_payload = {"artifact": artifact_name, "size": size,
                                      "attempts": upload.attempts, "mode": upload.mode}
        if missing_parts is not None:
            # for support: the parts that a bad network connection lost
            self.request_event_payload["missing_parts"] = missing_parts
        return {"mode": upload.mode, "key": upload.key,
                "expires_at": (timezone.now() + timedelta(seconds=UPLOAD_URL_EXPIRY)).isoformat(),
                **destination}

    def _max_size(self, job, storage):
        # the kind's ceiling under the deployment's, never above it. The definition is resolved: the
        # artifact lookup above already returned None for a kind this release cannot reach.
        ceiling = upload_max_size(storage)
        kind_max = job.definition.max_upload_size
        return min(kind_max, ceiling) if kind_max else ceiling

    def _check_pending(self, schedule_pk, run_id, artifact_name):
        # the row this request is about is excluded, so the bound falls on a NEW row and never on a
        # retry: an agent already at the limit can still finish the runs it holds, which is the only
        # way its rows ever clear.
        pending = JobUpload.objects.filter(
            schedule_pk=schedule_pk, serial_number=self.serial_number, status=UploadStatus.PENDING
        ).exclude(run_id=run_id, artifact=artifact_name).count()
        if pending >= MAX_PENDING_UPLOADS:
            # counted before the row is created, so a machine cycling run ids stops here instead of
            # collecting write credentials
            logger.warning("Turbo upload mint from %s: %s pending rows on schedule %s",
                           self.serial_number, pending, schedule_pk)
            raise WireError("too_many_pending", status=429)


class UploadCompleteView(BaseEnrolledMachinePostView):
    """`POST /public/turbo/uploads/complete/` — all the parts are uploaded, and the server completes the upload.

    The agent does not complete or abort with a presigned URL. That needs the ETags and a CompleteMultipartUpload
    body, and S3 can answer an error inside a 200 OK. The agent is a plain HTTP client, with no storage knowledge.

    202: S3 documents that the completion can take some minutes, so a Celery task does it, and records the
    verification on the row. The call is idempotent, so the agent can send it again.
    """
    request_type = "upload_complete"
    response_status = 202

    def do_post(self, data):
        # the run block of the mint, and the upload block with only the artifact name
        schedule_pk, run_id, _, artifact_name = _run_and_artifact(data)
        try:
            upload = JobUpload.objects.get(schedule_pk=schedule_pk, serial_number=self.serial_number,
                                           run_id=run_id, artifact=artifact_name)
        except JobUpload.DoesNotExist:
            raise WireError("unknown_upload")
        if upload.mode != UploadMode.MULTIPART or not upload.upload_id:
            # a single PUT is complete when the PUT returns. The mint response gives the mode, so this is
            # an error of the agent.
            raise WireError("not_multipart")
        self.request_event_payload = {"artifact": artifact_name}
        if upload.verification == UploadVerification.PENDING:
            # a decided verification is final. on_commit, because ATOMIC_REQUESTS can roll back the request.
            transaction.on_commit(
                lambda: complete_multipart_upload_task.apply_async((str(upload.pk),)))
        return {}


class HostedUploadView(View):
    """The fallback destination when the storage cannot presign a PUT.

    Same contract on the wire — the agent sees one `mode: "put"` shape and never learns which storage
    is behind it — but the body comes through gunicorn here, which is why the ceiling is small and
    why this is for development and small on-prem only. The token stands in for the presigned
    signature: it names one row, and it expires.

    JSON on every path, like the rest of the device API. This endpoint is reached by a URL the agent
    was handed rather than one it composed, so a Django HTML error page here is doubly useless: the
    agent has no parser for it and no other address to try.
    """
    def put(self, request, token, *args, **kwargs):
        upload_pk = unsign_hosted_upload(token)
        if upload_pk is None:
            return JsonResponse({"error": "invalid_token"}, status=403)
        try:
            upload = JobUpload.objects.get(pk=upload_pk)
        except (JobUpload.DoesNotExist, ValueError):
            return JsonResponse({"error": "unknown_upload"}, status=404)
        # A result closed the row. The token can still be valid, but a write now lands where no
        # result points.
        if upload.status == UploadStatus.UPLOADED:
            return JsonResponse({"error": "already_uploaded"}, status=409)
        if upload.status == UploadStatus.FAILED:
            return JsonResponse({"error": "already_failed"}, status=409)
        try:
            body = request.body
        except RequestDataTooBig:
            # the deployment's own body limit, which is also the ceiling the config published, so a
            # well-behaved agent was refused at the mint and never got here. This catches the one
            # that declared a size it did not send: without it Django answers a SuspiciousOperation
            # with an HTML page, on the one endpoint contracted never to serve one.
            logger.warning("Turbo hosted upload %s: body over the deployment limit", upload.pk)
            return JsonResponse({"error": "too_large"}, status=413)
        if len(body) != upload.size:
            # a presigned PUT has the length in the signature and the storage enforces it for us;
            # here there is nobody else to do it, and the size is what the mint was clamped against.
            # Before the digest, which a wrong length fails too — but says less about why.
            logger.warning("Turbo hosted upload %s: %s bytes declared, %s sent",
                           upload.pk, upload.size, len(body))
            return JsonResponse({"error": "size_mismatch"}, status=400)
        if hashlib.sha256(body).hexdigest() != upload.sha256:
            # S3 does this for the presigned path, from a header the agent cannot alter. Here there
            # is nobody else, and this is the ONLY point at which a filesystem storage can ever check
            # the digest — it reports no checksum, so the verification axis has nothing to read back.
            logger.warning("Turbo hosted upload %s: digest does not match", upload.pk)
            return JsonResponse({"error": "digest_mismatch"}, status=400)
        storage = storages["default"]
        # the key is stable for the life of the row, so a retry must overwrite it. storage.save()
        # would pick a free name instead and the object would stop matching the key we minted.
        if storage.exists(upload.key):
            storage.delete(upload.key)
        storage.save(upload.key, ContentFile(body))
        return JsonResponse({}, status=200)

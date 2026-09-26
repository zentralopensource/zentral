import hashlib
import logging
import uuid
from datetime import timedelta

from django.core.files.base import ContentFile
from django.core.files.storage import storages
from django.db import transaction
from botocore.exceptions import BotoCoreError, ClientError
from django.core.exceptions import RequestDataTooBig
from django.http import JsonResponse
from django.utils import timezone
from django.views.generic import View

from ..models import (JobUpload, ScheduleMode, UploadMode, UploadStatus, UploadVerification,
                      get_machine_schedule, one_time_gate_closed)
from ..tasks import complete_multipart_upload_task
from ..uploads import (MAX_PENDING_UPLOADS, MAX_UPLOAD_ATTEMPTS, UPLOAD_URL_EXPIRY,
                       build_upload_destination, build_upload_key, parse_digests, parse_sha256,
                       start_multipart_upload, unsign_hosted_upload, upload_max_size, upload_mode)
from .base import BaseEnrolledMachinePostView, WireError

logger = logging.getLogger("zentral.contrib.turbo.public_views.uploads")


def _uuid(data, key):
    value = data.get(key)
    if not isinstance(value, str):
        raise WireError(f"missing_{key}")
    try:
        return uuid.UUID(value)
    except ValueError:
        raise WireError(f"invalid_{key}")


def _part_numbers(value):
    """The part numbers of a resume, or None when the request is not one.

    A part number is what it says, so it is checked as one here rather than trusted into a range()
    below. The geometry the row holds decides which of them exist.
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
        schedule_pk = _uuid(data, "schedule_pk")
        # the run identity, and the reason this plane can serve a recurring schedule at all: without
        # it two runs of one schedule are indistinguishable and would share a row
        run_id = _uuid(data, "run_id")
        artifact_name = data.get("artifact")
        if not isinstance(artifact_name, str) or not artifact_name:
            raise WireError("missing_artifact")
        size = data.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise WireError("invalid_size")
        sha256 = parse_sha256(data.get("sha256"))
        if sha256 is None:
            raise WireError("invalid_sha256")
        digests = parse_digests(data.get("digests"))
        if digests is None:
            raise WireError("invalid_digests")
        # the resume block, both halves or neither: an upload_id names the multipart upload already in
        # flight, and missing_parts says which parts of it still need a URL
        upload_id = data.get("upload_id")
        if upload_id is not None and not isinstance(upload_id, str):
            raise WireError("invalid_upload_id")
        missing_parts = _part_numbers(data.get("missing_parts"))
        if missing_parts is not None and upload_id is None:
            # the resume shape is both keys. Without the id there is nothing to resume, and signing
            # part 3 of a multipart upload the agent has not started would hand it a URL for two
            # thirds of an object it can never finish.
            raise WireError("missing_upload_id")

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
            # a multipart object is validated by the whole-object CRC and by nothing else: sha256 is
            # composite-only on a multipart upload, so without this there is no value to complete
            # with and the assembled object would be accepted unchecked
            raise WireError("missing_digest")

        upload, _ = JobUpload.objects.get_or_create(
            schedule_pk=schedule.pk, serial_number=self.serial_number,
            run_id=run_id, artifact=artifact_name,
            defaults={"schedule_mode": schedule.wire_mode, "size": size, "sha256": sha256,
                      "crc64nvme": digests.get("crc64nvme", ""),
                      "crc32c": digests.get("crc32c", ""),
                      "mode": mode,
                      "key": ""},
        )
        if upload.status == UploadStatus.UPLOADED:
            # the artifact is already in, and for a one-time shot the partial unique index would
            # refuse a second one anyway
            raise WireError("already_uploaded", status=410)
        if upload.attempts >= MAX_UPLOAD_ATTEMPTS:
            raise WireError("attempts_exhausted")

        if upload.mode == UploadMode.MULTIPART and upload.upload_id:
            if upload_id is not None and upload_id != upload.upload_id:
                # the presented id is checked against the row, never believed: parts signed against a
                # different multipart upload would assemble somewhere nothing is looking
                raise WireError("unknown_upload_id")
            if (size, sha256) != (upload.size, upload.sha256):
                # the parts already up are the bytes this row describes, and the geometry was fixed
                # against that size when the multipart upload was created. A different artifact needs
                # its own upload, not a resume of this one — re-signing against a new geometry would
                # produce parts that cannot line up with what is already in flight.
                raise WireError("artifact_changed")

        # a retry re-signs the SAME key, so it overwrites in place instead of leaving a twin
        if not upload.key:
            upload.key = build_upload_key(upload, artifact)
        # the digests belong to the bytes, so they move with size and sha256 on a retry. Left on the
        # first mint's values they would describe bytes that are no longer the ones at the key, and
        # the verification axis would compare against the wrong digest.
        upload.size = size
        upload.sha256 = sha256
        upload.crc64nvme = digests.get("crc64nvme", "")
        upload.crc32c = digests.get("crc32c", "")
        if upload.mode == UploadMode.MULTIPART and not upload.upload_id:
            try:
                start_multipart_upload(upload, artifact, storage)
            except (BotoCoreError, ClientError):
                # the one storage call this endpoint makes, and a storage that does not answer is not
                # the agent's fault. Unhandled it would be an HTML 500 on an endpoint contracted never
                # to serve one, and ATOMIC_REQUESTS would roll the row back while the storage may
                # already hold the upload id — an orphan for the lifecycle rule to sweep. A retry-later
                # answer instead: the agent mints again, which is the right thing to do about a
                # storage that was busy.
                logger.exception("Turbo upload mint from %s: could not start the multipart upload",
                                 self.serial_number)
                raise WireError("storage_unavailable", status=503)
        upload.attempts += 1
        upload.save()

        destination = build_upload_destination(upload, artifact, storage, missing_parts)
        self.request_event_payload = {"artifact": artifact_name, "size": size,
                                      "attempts": upload.attempts, "mode": upload.mode}
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
    """`POST /public/turbo/uploads/complete/` — every part is up; the server closes the upload.

    There is no presigned complete and no presigned abort. Completing means collecting ETags,
    building a CompleteMultipartUpload body and, on S3, parsing an error out of a 200 OK — the one
    place the agent would have needed storage-specific knowledge, which is what "the agent is a plain
    HTTP client" was supposed to mean.

    202, because both storages document that assembling a multipart upload can take several minutes,
    so it cannot sit in a device request. The agent has nothing to do with the answer either: it
    uploaded the bytes, and whether the storage assembles them lands on the row's verification axis.
    Idempotent, so the agent can retry the call freely.
    """
    request_type = "upload_complete"
    response_status = 202

    def do_post(self, data):
        schedule_pk = _uuid(data, "schedule_pk")
        run_id = _uuid(data, "run_id")
        artifact_name = data.get("artifact")
        if not isinstance(artifact_name, str) or not artifact_name:
            raise WireError("missing_artifact")
        try:
            upload = JobUpload.objects.get(schedule_pk=schedule_pk, serial_number=self.serial_number,
                                           run_id=run_id, artifact=artifact_name)
        except JobUpload.DoesNotExist:
            raise WireError("unknown_upload")
        if upload.mode != UploadMode.MULTIPART or not upload.upload_id:
            # a single PUT is finished when its PUT returns, and `mode` is how the agent knows which
            # it has — asking for this one is a contract error, not a transient one
            raise WireError("not_multipart")
        self.request_event_payload = {"artifact": artifact_name}
        if upload.verification != UploadVerification.VERIFIED:
            # on_commit like every other enqueue here: ATOMIC_REQUESTS means a task started now could
            # run against a transaction that never lands
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
        if upload.status == UploadStatus.UPLOADED:
            return JsonResponse({"error": "already_uploaded"}, status=409)
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

import logging
import re

from django.conf import settings
from django.core.signing import BadSignature, TimestampSigner
from django.urls import reverse
from django.utils import timezone

from zentral.conf import api_base_url
from zentral.utils.storage import (create_multipart_upload, file_storage_has_presigned_uploads,
                                   generate_presigned_part, generate_presigned_put, sha256_object,
                                   stat_object)

from .models import UploadMode, UploadVerification


logger = logging.getLogger("zentral.contrib.turbo.uploads")


# How long a minted URL is good for. Generous, because the agent may be uploading hundreds of
# megabytes over a hotel connection, and a signature is checked at request START — a slow upload that
# begins in time finishes.
UPLOAD_URL_EXPIRY = 3600

# The DEPLOYMENT ceiling on one artifact, which the config response publishes so the agent can fail
# fast instead of compressing 2 GiB it will not be allowed to send. The per-kind maxima clamp below
# it, server-side at mint.
PRESIGNED_UPLOAD_MAX_SIZE = 2 * 2**30
# what to publish when the deployment disables Django's body limit. The shipped nginx configurations
# cap at 10 MiB, so anything larger is the same mismatch again — a ceiling the agent is told about and
# a wall it meets. A deployment that raised its proxy can raise DATA_UPLOAD_MAX_MEMORY_SIZE too.
HOSTED_UPLOAD_MAX_SIZE_UNDECLARED = 10 * 2**20


def hosted_upload_max_size():
    """The ceiling without a presigned storage, which is not ours to pick.

    Without one the body comes through gunicorn, the known worker-timeout failure class, so this
    fallback is for development and small on-prem only. The deployment already declares what a
    request body may weigh, and reading request.body past it raises RequestDataTooBig — so that is
    the number. Publishing any other is publishing a wall the agent cannot see: it spends the
    artifact, the upload and every retry discovering it. The shipped nginx configurations set
    client_max_body_size to match, and a deployment that raises one must raise both.

    None means the deployment declined to declare one. Nothing then stops a worker reading an
    unbounded body, so the number is ours again — and being ours, it matches the shipped proxies.
    """
    declared = settings.DATA_UPLOAD_MAX_MEMORY_SIZE
    return HOSTED_UPLOAD_MAX_SIZE_UNDECLARED if declared is None else declared


# Storage-native digests to fold into the agent's single read pass, on top of sha256, which is always
# computed because it is Zentral's own identity for the artifact. crc64nvme is published from the
# start even though only multipart enforces it: the server picks the mode, so an agent that hashed
# only for the mode it expected would need a re-read the day the threshold moves.
PRESIGNED_UPLOAD_DIGESTS = ["crc64nvme"]
HOSTED_UPLOAD_DIGESTS = []

# Mints that handed out URLs, per row. The agent gives up at five of its own accord; this is the same
# number enforced where it cannot be argued with.
MAX_UPLOAD_ATTEMPTS = 5

# Rows a machine may hold open on one schedule. MAX_UPLOAD_ATTEMPTS bounds a row, and nothing bounded
# the rows: run_id is the agent's to choose, and a gate only closes on a result, so a machine that
# never reports could mint a fresh row — and a fresh write credential — for every id it invented. A
# version bump re-arms a one-time job, so more than one open run is legitimate; a dozen is not.
MAX_PENDING_UPLOADS = 12

# The slicing rule for a multipart upload. Server-side only — the agent reads the geometry off the
# mint response, so retuning this needs no protocol change and no agent release.
MULTIPART_PART_SIZE = 64 * 2**20
# TWO part sizes and not one. Resumability is the entire point, and at one there is none to buy: a
# part_size + 1 artifact is a two-part upload whose second part is one byte, so losing the first part
# costs the same retransmission that restarting a single PUT would have. The whole multipart bill —
# an upload id on the row, N signed URLs, a device-facing completion call, a queue task and a
# lifecycle obligation for parts that never complete — would be paid to protect a one-byte tail. At
# two, the first failure loses at most half the transfer, so a resume saves at least one whole part.
# That is the line: multipart starts paying when a resume can save a full part.
MULTIPART_THRESHOLD = 2 * MULTIPART_PART_SIZE

_UNSAFE_KEY_CHARS = re.compile(r"[^A-Za-z0-9._-]")
# a length check is not a format check: a 64-character non-hex digest passes one and reaches the
# encoder, which cannot unhexlify it — on a device endpoint that is a 500 instead of a 400 the agent
# could act on. Case-insensitive because an agent formatting with %X is not wrong; stored lowercase
# so the comparison at verification time has one form to consider.
_SHA256 = re.compile(r"\A[0-9a-fA-F]{64}\Z")
# base64 of an 8-byte CRC is 12 characters, of a 4-byte one 8; the columns hold 32. Anything else is
# not a digest, and an over-long value would reach Postgres as a DataError.
_DIGEST = re.compile(r"\A[A-Za-z0-9+/]{1,30}={0,2}\Z")

_hosted_upload_signer = TimestampSigner(salt="zentral.contrib.turbo.uploads")


def upload_max_size(storage=None):
    return PRESIGNED_UPLOAD_MAX_SIZE if file_storage_has_presigned_uploads(storage) else hosted_upload_max_size()


def upload_mode(size, storage):
    """Single PUT or multipart, and entirely the server's business.

    The agent sends the same mint body either way and reads the mode off the response, so there is
    nothing for it to predict, no part size to cache, and no stale-configuration two-step. Nothing
    forces the choice either: S3's single-PUT ceiling is 5 GiB against a 2 GiB upload_max_size, so a
    single PUT is legal for every artifact Zentral accepts and multipart is purely an optimisation.
    """
    if size >= MULTIPART_THRESHOLD and file_storage_has_presigned_uploads(storage):
        return UploadMode.MULTIPART
    return UploadMode.PUT


def part_lengths(size, part_size):
    """The exact length of every part, in order.

    Returned rather than computed at the call site so the slicing falls out of the mint response —
    the agent reads a Content-Length per part instead of reproducing this division.
    """
    full, tail = divmod(size, part_size)
    lengths = [part_size] * full
    if tail:
        lengths.append(tail)
    return lengths


def upload_digests(storage=None):
    return list(PRESIGNED_UPLOAD_DIGESTS if file_storage_has_presigned_uploads(storage)
                else HOSTED_UPLOAD_DIGESTS)


def parse_sha256(value):
    """The wire's sha256, lowercased — or None when it is not one."""
    if not isinstance(value, str) or not _SHA256.match(value):
        return None
    return value.lower()


def parse_digests(value):
    """The wire's storage digests, or None when the block is not usable.

    Unknown algorithms are dropped rather than refused: the set the server asks for can grow, and an
    agent that computed one this release does not store has done nothing wrong.
    """
    if value is None:
        return {}
    if not isinstance(value, dict):
        return None
    digests = {}
    for algorithm in ("crc64nvme", "crc32c"):
        digest = value.get(algorithm)
        if digest is None:
            continue
        if not isinstance(digest, str) or not _DIGEST.match(digest):
            return None
        digests[algorithm] = digest
    return digests


def _safe(component):
    # A serial number is whatever the agent said it was, and it lands in the object key. A serial
    # holding a "/" would restructure the path, and one holding a space or a quote would make the key
    # awkward everywhere it is later echoed. Substitute rather than reject: the machine is enrolled,
    # its artifact is legitimate, and the key is ours to choose.
    safe = _UNSAFE_KEY_CHARS.sub("_", component)
    # dots survive that substitution, so a serial of "." or ".." would still be a traversal segment —
    # harmless on S3, where a key is an opaque string, but the fallback storage is a filesystem
    if not safe.strip("."):
        return "unknown"
    return safe


def build_upload_key(upload, artifact):
    """The object key, built by the server and stable for the life of the row.

    Stable matters twice: a retry re-signs the same key and overwrites in place instead of leaving a
    half-written twin, and the filename — built from the artifact declaration, the serial and the
    row's FIRST mint time — is what a browser saves, so no rename is needed anywhere later. First
    mint time rather than now, so a retry does not move the object. The agent's run_id never appears:
    the path segment is the row's own pk.
    """
    serial_number = _safe(upload.serial_number)
    minted_at = (upload.created_at or timezone.now()).strftime("%Y%m%d-%H%M%S")
    filename = f"{artifact.stem}_{serial_number}_{minted_at}{artifact.extension}"
    return f"turbo/uploads/{serial_number}/{upload.schedule_pk}/{upload.pk}/{filename}"


def sign_hosted_upload(upload):
    return _hosted_upload_signer.sign(str(upload.pk))


def unsign_hosted_upload(token):
    """The upload pk a hosted-upload token names, or None if it is forged or too old."""
    try:
        return _hosted_upload_signer.unsign(token, max_age=UPLOAD_URL_EXPIRY)
    except BadSignature:
        return None


def verify_upload(upload, reported, storage):
    """Does the storage agree with what the agent reported? The SECOND axis.

    It cannot reopen a spent shot. This runs after the gate has closed, and its whole output is the
    row's verification field and the flag that rides into the result event — "the agent says it
    uploaded" and "the storage agrees" stay two facts.

    The size and the digest reach here by two independent paths. One went out at the mint and was
    SIGNED into the upload, so the storage refused any body that did not match it, and comes back as
    the checksum the storage recorded. The other came home in the result. Verification is where the
    two copies meet, and on a storage that signs, Zentral reads no byte to compare them.

    Both legs are checked. An agent whose result contradicts its own mint is describing a different
    file, and comparing the stored object against the mint alone would miss it — on a signing storage
    that comparison is nearly tautological, since S3 enforced it on the way in.

    Returns an UploadVerification value, or None when nothing could be decided. Undecided is a real
    answer and deliberately not `missing`: a storage that timed out, a key we may not read, or an
    object something else wrote without a checksum are all "ask again later", and a transient blip
    that permanently marked artifacts missing would be worse than no answer at all.
    """
    if not _report_agrees_with_the_mint(upload, reported):
        return UploadVerification.MISMATCH
    try:
        stored = stat_object(upload.key, storage=storage)
    except Exception:
        logger.exception("Could not stat turbo upload %s", upload.pk)
        return None
    if stored is None:
        return UploadVerification.MISSING
    if stored["size"] != upload.size:
        return UploadVerification.MISMATCH
    sha256 = stored["sha256"]
    if sha256 is None and not file_storage_has_presigned_uploads(storage):
        # nothing signed this body on the way in and the storage keeps no digest, so the only way to
        # know is to read it — which is affordable exactly because a storage that cannot sign an
        # upload has the small ceiling
        try:
            sha256 = sha256_object(upload.key, storage=storage)
        except Exception:
            logger.exception("Could not hash turbo upload %s", upload.pk)
            return None
    if sha256 is None:
        # the storage can sign, so every object we put there carries the checksum we signed. One that
        # does not was written by something else, and saying so is more useful than a verdict.
        logger.error("Turbo upload %s: no stored sha256 at %s", upload.pk, upload.key)
        return None
    return UploadVerification.VERIFIED if sha256 == upload.sha256 else UploadVerification.MISMATCH


def _report_agrees_with_the_mint(upload, reported):
    # the result echoes the size and the digest a second time. Where it does, they have to be the
    # ones the mint signed: an agent that asks for a destination for one file and reports another has
    # told us about two files, and only one of them is at the key. Absent values are not a
    # contradiction — the row is what was signed either way.
    for attribute, declared in (("size", upload.size), ("sha256", upload.sha256)):
        echoed = reported.get(attribute)
        if isinstance(echoed, str):
            # parse_sha256 stores the digest lowercase, so the echo is read the same way
            echoed = echoed.lower()
        if echoed is not None and echoed != declared:
            logger.warning("Turbo upload %s: reported %s %r contradicts the minted %r",
                           upload.pk, attribute, echoed, declared)
            return False
    return True


def build_upload_destination(upload, artifact, storage, missing_parts=None):
    """Where to send the artifact, as the mode-specific half of the mint response.

    A single PUT is one url and the headers to send with it, and the two single-PUT branches produce
    the same shape on the wire so the agent has no storage to detect. What differs is who validates
    the body: a presigned PUT signs the length and the digest as headers, so the storage rejects a
    mismatch and Zentral never reads a byte; the hosted fallback has to read it, which is exactly why
    its ceiling is small.

    A multipart upload is the geometry plus one presigned URL per part. The geometry comes back WITH
    the URLs, which is the whole reason it is not published or cached anywhere.
    """
    if upload.mode == UploadMode.MULTIPART:
        return {"upload_id": upload.upload_id,
                "part_size": upload.part_size,
                "parts": _presigned_parts(upload, storage, missing_parts)}
    if file_storage_has_presigned_uploads(storage):
        url, headers = generate_presigned_put(
            upload.key, upload.size, artifact.content_type, upload.sha256, UPLOAD_URL_EXPIRY,
            storage=storage,
        )
    else:
        url = "{}{}".format(api_base_url(),
                            reverse("turbo_public:upload", args=(sign_hosted_upload(upload),)))
        headers = {"Content-Type": artifact.content_type, "Content-Length": str(upload.size)}
    return {"url": url, "headers": headers}


def _presigned_parts(upload, storage, missing_parts):
    # against the row's OWN part_size, fixed when the multipart upload was created: a resume has to
    # produce parts that line up with the object already in flight, so a change to the deployment's
    # default in the meantime must not reach it
    lengths = part_lengths(upload.size, upload.part_size)
    wanted = range(1, len(lengths) + 1)
    if missing_parts is not None:
        # a resume signs only what is still needed, and only numbers this geometry actually has
        wanted = [n for n in missing_parts if 1 <= n <= len(lengths)]
    parts = []
    for number in wanted:
        url, headers = generate_presigned_part(
            upload.key, upload.upload_id, number, lengths[number - 1], UPLOAD_URL_EXPIRY, storage,
        )
        parts.append({"n": number, "url": url, "headers": headers})
    return parts


def start_multipart_upload(upload, artifact, storage):
    """Create the multipart upload the row will hold for the rest of its life.

    Once, on the first mint that chose multipart: the upload id and the part size are then the row's,
    and every resume re-signs against them.
    """
    upload.upload_id = create_multipart_upload(upload.key, artifact.content_type, storage)
    upload.part_size = MULTIPART_PART_SIZE

import base64
import binascii
import hashlib

from django.core.files.storage import storages, InvalidStorageError


# A HEAD, or starting a multipart upload, is a single small round trip — tens of milliseconds — but it
# happens on a device endpoint, inside the request transaction, so it gets an explicit ceiling instead
# of botocore's minute-scale defaults: an unbounded call to a storage that has gone quiet holds a web
# worker AND a database connection.
_REQUEST_CONNECT_TIMEOUT = 2
_REQUEST_READ_TIMEOUT = 5

# Assembling a multipart upload is the exception: both storages document that it can take several
# MINUTES, which is why it runs in a worker and not in a request. The ceiling is there to bound a
# connection that died rather than to bound the operation, and the retrying is the task's, with
# backoff, rather than botocore's.
_ASSEMBLY_CONNECT_TIMEOUT = 5
_ASSEMBLY_READ_TIMEOUT = 600

# total, not retries: botocore reads `max_attempts` as the number of RETRIES and stores
# max_attempts + 1, so the obvious spelling of "once" asks for twice and doubles the worst case these
# ceilings exist to bound. total_max_attempts is the key it keeps, and it means what it says. One
# attempt for both: the caller of a request-path call treats "could not tell" as a normal outcome it
# can ask about again later, and the assembly is retried by its task, with backoff.
_ONE_ATTEMPT = {"mode": "standard", "total_max_attempts": 1}

# The one line of the multipart design that must not be dropped. Declaring the algorithm at
# CreateMultipartUpload is what makes the checksum supplied at completion actually validate: without
# it S3 accepts a WRONG whole-object checksum silently, and HeadObject afterwards reports a perfectly
# correct one, because S3 computed its own — the object looks verified and is not. CRC64NVME and not
# SHA-256 because S3 offers a full-object checksum on a multipart upload only for the CRC algorithms:
# only those compose from part checksums into a checksum of the whole object.
MULTIPART_CHECKSUM_ALGORITHM = "CRC64NVME"


def file_storage_has_signed_urls(storage=None):
    if storage is None:
        storage = storages["default"]
    # TODO better detection!
    storage_class_name = storage.__class__.__name__
    return storage_class_name in ('S3Storage', 'S3Boto3Storage', 'GoogleCloudStorage', 'ZentralGoogleCloudStorage')


def file_storage_has_presigned_uploads(storage=None):
    """Whether the storage can hand a client a URL to PUT an object to directly.

    Narrower than file_storage_has_signed_urls: signing a *download* is a read of an object the server
    already has, signing an *upload* delegates a write. Only the S3 backends do it here; a deployment
    without it keeps the same contract through a Zentral-hosted endpoint, with a much tighter size cap
    because a large body through gunicorn is a worker timeout waiting to happen.
    """
    if storage is None:
        storage = storages["default"]
    return storage.__class__.__name__ in ('S3Storage', 'S3Boto3Storage')


def _sha256_base64(sha256_hex):
    # the wire carries sha256 as hex, S3 wants base64. Doing it here rather than at the call site
    # keeps "what encoding this storage wants" in one place — a caller that got it wrong would sign a
    # header the client cannot reproduce, and every upload would fail at the storage.
    try:
        return base64.b64encode(binascii.unhexlify(sha256_hex)).decode("ascii")
    except (binascii.Error, ValueError):
        raise ValueError(f"Not a hex sha256: {sha256_hex!r}")


def _s3_client(storage, cache_attr, **config_kwargs):
    # a client of the storage's OWN session, so it authenticates exactly like the storage does, with
    # the deployment's config merged under ours. Cached on the storage, which Django keeps as a
    # singleton; racing threads would build a second one and use it safely.
    client = getattr(storage, cache_attr, None)
    if client is None:
        from botocore.client import Config
        session = storage._create_session()
        client = session.client(
            "s3",
            region_name=storage.region_name,
            use_ssl=storage.use_ssl,
            endpoint_url=storage.endpoint_url,
            verify=storage.verify,
            config=storage.client_config.merge(Config(**config_kwargs)),
        )
        setattr(storage, cache_attr, client)
    return client


def _presigning_client(storage):
    """A client that signs with SigV4, whatever the deployment left unset.

    botocore only presigns with SigV4 when the signature version was set EXPLICITLY. Where it is
    merely resolved from the endpoint — the default in us-east-1, and behind any custom endpoint_url
    — generate_presigned_url falls back to the legacy V2 query signature. Content-Length is then not
    signed at all, and the checksum is a query parameter S3 does not read: the storage would accept
    any body of any size, and the guarantee below would be gone with nothing to see. So the version
    is forced here rather than trusted, on a client of the storage's own session so that uploads
    authenticate exactly like downloads.
    """
    return _s3_client(storage, "_zentral_presigning_client", signature_version="s3v4")


def _request_client(storage):
    """A client for the storage calls made inside a device request, with a ceiling the deployment's
    config cannot lift.

    Unlike the presigning client these talk to the network, on a device endpoint, inside the request
    transaction — so an unbounded call to a storage that has gone quiet would hold a web worker AND a
    database connection. One attempt, deliberately: a retry would double how long that transaction
    stays open to buy an answer that was never urgent, and the callers treat "could not tell" as a
    normal outcome they can ask about again later.
    """
    return _s3_client(storage, "_zentral_request_client",
                      connect_timeout=_REQUEST_CONNECT_TIMEOUT,
                      read_timeout=_REQUEST_READ_TIMEOUT,
                      retries=_ONE_ATTEMPT)


def _assembly_client(storage):
    """The one client allowed to wait minutes, for the one call that takes them, in a worker."""
    return _s3_client(storage, "_zentral_assembly_client",
                      connect_timeout=_ASSEMBLY_CONNECT_TIMEOUT,
                      read_timeout=_ASSEMBLY_READ_TIMEOUT,
                      retries=_ONE_ATTEMPT)


def _object_key(storage, key):
    """The key S3 actually holds the object under.

    With a `location` set, S3Storage prefixes every key it reads, so a bare name would write — and
    look — outside the namespace that exists(), delete(), url() and the verification HEAD all share.
    A private accessor, but it is the one url() itself uses, and there is no public equivalent: the
    paths that sign a write and the paths that read it back have to agree on one string.
    """
    from storages.utils import clean_name
    return storage._normalize_name(clean_name(key))


def generate_presigned_put(key, size, content_type, sha256_hex, expires_in, storage=None):
    """A presigned single PUT, and the headers the client must send with it verbatim.

    Everything declared here is signed as a HEADER, not as a query parameter — content-length,
    content-type and the checksum — so the storage itself rejects a body that does not match what was
    declared, and Zentral never reads a byte to find out. The client cannot alter any of them without
    invalidating the signature, which is the point: the size and the digest travel to the storage by a
    different path than the one they travel back on.
    """
    if storage is None:
        storage = storages["default"]
    client = _presigning_client(storage)
    headers = {
        "Content-Type": content_type,
        "Content-Length": str(size),
        "x-amz-checksum-sha256": _sha256_base64(sha256_hex),
    }
    url = client.generate_presigned_url(
        "put_object",
        Params={
            "Bucket": storage.bucket_name,
            "Key": _object_key(storage, key),
            "ContentType": content_type,
            "ContentLength": size,
            "ChecksumSHA256": headers["x-amz-checksum-sha256"],
        },
        ExpiresIn=expires_in,
    )
    return url, headers


def _sha256_hex(checksum_base64):
    # the other direction of _sha256_base64: S3 reports the checksum it recorded in base64, and every
    # caller compares it against the hex the wire carries
    if not checksum_base64:
        return None
    try:
        return binascii.hexlify(base64.b64decode(checksum_base64, validate=True)).decode("ascii")
    except (binascii.Error, ValueError):
        return None


def stat_object(key, storage=None):
    """The stored size and the whole-object digests the storage itself recorded.

    Returns None when there is nothing at the key — and only then. Every other failure raises, so a
    storage that is unreachable or a key we may not read is never mistaken for an object that is not
    there.

    Two S3 details this depends on. HeadObject reports a checksum only when the request asks for it,
    so without ChecksumMode the response is silently checksum-free and a comparison against it would
    pass for any object at all. And a missing key surfaces as the bare status 404, not NoSuchKey —
    HeadObject has no body to carry an error code — so an `except NoSuchKey` would never fire.
    """
    if storage is None:
        storage = storages["default"]
    if file_storage_has_presigned_uploads(storage):
        from botocore.exceptions import ClientError
        client = _request_client(storage)
        try:
            response = client.head_object(Bucket=storage.bucket_name, Key=_object_key(storage, key),
                                          ChecksumMode="ENABLED")
        except ClientError as error:
            if error.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 404:
                return None
            raise
        return {"size": response["ContentLength"],
                "sha256": _sha256_hex(response.get("ChecksumSHA256")),
                "crc64nvme": response.get("ChecksumCRC64NVME") or None}
    if not storage.exists(key):
        return None
    # a storage with no checksum of its own: the size is all a stat can say, and a caller that needs
    # the digest has to read the object
    return {"size": storage.size(key), "sha256": None, "crc64nvme": None}


def sha256_object(key, storage=None):
    """Read the object and hash it, for a storage that records no digest of its own.

    Only ever called against a storage that cannot presign an upload, where the size cap is small
    enough for this to be a local read.
    """
    if storage is None:
        storage = storages["default"]
    digest = hashlib.sha256()
    with storage.open(key, "rb") as stored:
        for chunk in stored.chunks():
            digest.update(chunk)
    return digest.hexdigest()


def create_multipart_upload(key, content_type, storage):
    """Start a multipart upload, and DECLARE the checksum algorithm.

    Every call of this plane names the object through _object_key: with a `location` set, a bare key
    would start the upload, sign its parts, list them and complete them outside the namespace the
    rest of the storage reads, and the object would land where nothing looks for it.

    The declaration is what makes the value supplied at completion validate anything — see
    MULTIPART_CHECKSUM_ALGORITHM. ChecksumType and the object size at completion are genuinely
    optional (CRC64NVME defaults to full-object), and are sent for clarity; the algorithm is not
    optional, and its optionality elsewhere must not be read as license to drop it.
    """
    response = _request_client(storage).create_multipart_upload(
        Bucket=storage.bucket_name,
        Key=_object_key(storage, key),
        ContentType=content_type,
        ChecksumAlgorithm=MULTIPART_CHECKSUM_ALGORITHM,
        ChecksumType="FULL_OBJECT",
    )
    return response["UploadId"]


def generate_presigned_part(key, upload_id, part_number, size, expires_in, storage):
    """A presigned UploadPart, and the one header that goes with it.

    Geometry only: a part carries no checksum on either storage, so the length is the entire contract
    — and it is a SIGNED header, which is why this goes through the SigV4 client like every other
    presign here. The legacy V2 presign signs no header at all, and a part could then be any size.
    """
    url = _presigning_client(storage).generate_presigned_url(
        "upload_part",
        Params={"Bucket": storage.bucket_name, "Key": _object_key(storage, key),
                "UploadId": upload_id, "PartNumber": part_number, "ContentLength": size},
        ExpiresIn=expires_in,
    )
    return url, {"Content-Length": str(size)}


def list_multipart_parts(key, upload_id, storage):
    """The parts the storage is holding, as CompletedPart entries in part order.

    Paginated, because reading a truncated first page as the whole list would assemble a partial
    object and call it done. Zentral's own geometry cannot fill a page — which is exactly why a
    truncated answer must not be mistaken for a complete one.
    """
    paginator = _assembly_client(storage).get_paginator("list_parts")
    parts = []
    for page in paginator.paginate(Bucket=storage.bucket_name, Key=_object_key(storage, key),
                                   UploadId=upload_id):
        for part in page.get("Parts", ()):
            parts.append({"PartNumber": part["PartNumber"], "ETag": part["ETag"]})
    parts.sort(key=lambda part: part["PartNumber"])
    return parts


def complete_multipart_upload(key, upload_id, parts, crc64nvme, object_size, storage):
    """Assemble the object, and let the storage refuse it if the bytes are not what was declared.

    The part list comes from the storage, never from a client. The whole-object checksum is the one
    the agent declared before it sent a byte, and S3 computes the assembled object's own and answers
    BadDigest on a mismatch — because the algorithm was declared at create.
    """
    return _assembly_client(storage).complete_multipart_upload(
        Bucket=storage.bucket_name,
        Key=_object_key(storage, key),
        UploadId=upload_id,
        MultipartUpload={"Parts": parts},
        ChecksumCRC64NVME=crc64nvme,
        ChecksumType="FULL_OBJECT",
        MpuObjectSize=object_size,
    )


def abort_multipart_upload(key, upload_id, storage):
    """Drop the parts of an upload that will never complete.

    Parts of an abandoned multipart upload are stored, and billed, until something removes them. The
    bucket's AbortIncompleteMultipartUpload rule is the backstop; this is the fast path, for the
    cases where the agent told us it gave up.
    """
    _request_client(storage).abort_multipart_upload(
        Bucket=storage.bucket_name, Key=_object_key(storage, key), UploadId=upload_id)


def generate_presigned_get(key, filename, storage):
    """A signed GET, asking the storage to hand the object over rather than render it.

    The key already ends in the artifact's filename, so a browser saves the right name from the path
    alone — but a small manifest.json would open in the tab rather than be saved, and the disposition
    is what settles that. It is signed with the URL, so it cannot be stripped off on the way.

    S3 only. The two storages spell the option differently — GCS calls it response_disposition, on
    generate_signed_url — and the subclass Zentral uses to sign through IAM signBlob overrides url()
    without the parameters argument at all, so passing one there is a TypeError rather than a wrong
    header. A GCS deployment gets a plain signed URL and a manifest that opens in the tab.
    """
    if not file_storage_has_presigned_uploads(storage):
        return storage.url(key)
    return storage.url(key, parameters={
        "ResponseContentDisposition": f'attachment; filename="{filename}"'})


def select_dist_storage():
    try:
        return storages["dist"]
    except InvalidStorageError:
        return storages["default"]

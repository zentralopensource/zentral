import base64
import hashlib
from contextlib import contextmanager
from datetime import timedelta

from django.core.files.storage import storages, InvalidStorageError


# The limits of a storage call inside a device request: a metadata read, or the start of a multipart upload.
# While the call waits, it holds a web worker and a database connection. The default limits of botocore and
# of the GCS client are some minutes, and a retry doubles the wait, so one short attempt only.
# See _s3_request_client and _gcs_stat_object.
_REQUEST_CONNECT_TIMEOUT = 2
_REQUEST_READ_TIMEOUT = 5

# The limits of a storage call in a Celery task, which can wait. S3 documents that the completion of a
# multipart upload can take some minutes. Some attempts are for an outage of some seconds. After a longer
# outage, the call raises StorageUnavailable, and the caller must ask again later.
_TASK_CONNECT_TIMEOUT = 5
_TASK_READ_TIMEOUT = 600
_TASK_ATTEMPTS = 3


# Errors. The operations raise only these, never an exception of a storage library.


class StorageError(Exception):
    """A storage call failed, and no subclass gives the cause."""


class StorageUnavailable(StorageError):
    """The storage did not answer, or it asked for fewer requests. The same call can succeed later."""


class MultipartUploadNotFound(StorageError):
    """The storage has no multipart upload with this id. The upload is complete, or it was aborted."""


class MultipartUploadRefused(StorageError):
    """The storage refuses to assemble the parts. The same call cannot succeed later."""


def select_dist_storage():
    try:
        return storages["dist"]
    except InvalidStorageError:
        return storages["default"]


# Capabilities. A caller asks these, never which storage it has.


def file_storage_has_signed_urls(storage=None):
    if storage is None:
        storage = storages["default"]
    return _is_s3_storage(storage) or _is_gcs_storage(storage)


def file_storage_signed_url_expiration(storage=None):
    if storage is None:
        storage = storages["default"]
    if not file_storage_has_signed_urls(storage) or not getattr(storage, "querystring_auth", True):
        return None
    # GCS
    expiration = getattr(storage, "expiration", None)
    if isinstance(expiration, timedelta):
        return expiration
    # S3
    querystring_expire = getattr(storage, "querystring_expire", None)
    if querystring_expire:
        return timedelta(seconds=int(querystring_expire))
    return None


def file_storage_has_presigned_uploads(storage=None):
    """Whether the storage can hand a client a URL to PUT an object to directly.

    Narrower than file_storage_has_signed_urls: signing a *download* is a read of an object the server
    already has, signing an *upload* delegates a write. Only the S3 backends do it here; a deployment
    without it keeps the same contract through a Zentral-hosted endpoint, with a much tighter size cap
    because a large body through gunicorn is a worker timeout waiting to happen.
    """
    if storage is None:
        storage = storages["default"]
    return _is_s3_storage(storage)


def file_storage_has_multipart_uploads(storage=None):
    """True if a client can upload parts to presigned URLs, and the storage can assemble them.

    This is not file_storage_has_presigned_uploads(). GCS can presign a single PUT, but Zentral does not
    use the GCS multipart API.
    """
    if storage is None:
        storage = storages["default"]
    return _is_s3_storage(storage)


def file_storage_recorded_digests(storage=None):
    """The whole-object digests that the storage records, and that stat_object() returns.

    S3 records the checksum that a presigned upload declares: the SHA-256 of a single PUT, the
    CRC64NVME of a multipart upload. GCS records a CRC32C of every object. The file system storage
    records none, so a caller that needs a digest there must read the object.
    """
    if storage is None:
        storage = storages["default"]
    if _is_s3_storage(storage):
        return ("sha256", "crc64nvme")
    if _is_gcs_storage(storage):
        return ("crc32c",)
    return ()


# Operations. A caller passes any storage. The S3 and GCS implementations are below.


def generate_presigned_put(key, size, content_type, sha256_hex, expires_in, storage=None):
    """A presigned single PUT, and the headers the client must send with it verbatim.

    Everything declared here is signed as a HEADER, not as a query parameter — content-length,
    content-type and the checksum — so the storage itself rejects a body that does not match what was
    declared, and Zentral never reads a byte to find out. The client cannot alter any of them without
    invalidating the signature, which is the point: the size and the digest travel to the storage by a
    different path than the one they travel back on.

    Only S3 presigns an upload. A caller asks file_storage_has_presigned_uploads() first.
    """
    if storage is None:
        storage = storages["default"]
    if _is_s3_storage(storage):
        return _s3_presigned_put(storage, key, size, content_type, sha256_hex, expires_in)
    _refuse(storage, "presign an upload")


def generate_presigned_get(key, filename, storage):
    """A signed URL that downloads the object.

    The key ends with the file name, but a browser opens a small JSON file in the tab. On S3, the URL
    also signs a Content-Disposition, so the browser saves the file with this name. A GCS URL has no
    disposition, because ZentralGoogleCloudStorage.url() takes no parameters.
    """
    if _is_s3_storage(storage):
        return _s3_presigned_get(storage, key, filename)
    return storage.url(key)


def stat_object(key, storage=None):
    """The stored size, and the digests of file_storage_recorded_digests() as hex.

    Returns {"size": int, "digests": {name: hex or None}}, with one entry for each recorded digest:
    None when the storage has no value of that digest for this object. Reads metadata only, never the
    object.

    Returns None only when no object is at the key. All other failures raise a StorageError, so that an
    unavailable storage or a refused read never looks like a missing object.
    """
    if storage is None:
        storage = storages["default"]
    if _is_s3_storage(storage):
        return _s3_stat_object(storage, key)
    if _is_gcs_storage(storage):
        return _gcs_stat_object(storage, key)
    # the file system storage, which records no digest
    if not storage.exists(key):
        return None
    return {"size": storage.size(key), "digests": {}}


def sha256_object(key, storage=None):
    """Read the object and hash it, for a storage that records no digest of its own.

    Only called against the file system storage of a development or small on-premises deployment,
    where this is a local read under a small size cap. S3 and GCS report a digest instead.
    """
    if storage is None:
        storage = storages["default"]
    digest = hashlib.sha256()
    with storage.open(key, "rb") as stored:
        for chunk in stored.chunks():
            digest.update(chunk)
    return digest.hexdigest()


def create_multipart_upload(key, content_type, storage):
    """Start a multipart upload with a declared whole-object checksum, and return its id.

    Call file_storage_has_multipart_uploads() first. Raises a StorageError if the call fails.
    """
    if _is_s3_storage(storage):
        return _s3_create_multipart_upload(storage, key, content_type)
    _refuse(storage, "upload in parts")


def generate_presigned_part(key, upload_id, part_number, size, expires_in, storage):
    """A presigned URL for one part, and the headers that the client must send without change."""
    if _is_s3_storage(storage):
        return _s3_presigned_part(storage, key, upload_id, part_number, size, expires_in)
    _refuse(storage, "upload in parts")


def list_multipart_parts(key, upload_id, storage):
    """The parts that the storage has for an upload, in the order and format of the completion.

    Raises MultipartUploadNotFound if the upload is complete or aborted, and a StorageError for other failures.
    """
    if _is_s3_storage(storage):
        return _s3_list_multipart_parts(storage, key, upload_id)
    _refuse(storage, "upload in parts")


def complete_multipart_upload(key, upload_id, parts, crc64nvme, object_size, storage):
    """Assemble the object. The storage refuses the bytes if they do not agree with the declared checksum.

    Raises MultipartUploadRefused if the parts cannot make the declared object, MultipartUploadNotFound if
    the upload is complete or aborted, and a StorageError for other failures.
    """
    if _is_s3_storage(storage):
        return _s3_complete_multipart_upload(storage, key, upload_id, parts, crc64nvme, object_size)
    _refuse(storage, "upload in parts")


def abort_multipart_upload(key, upload_id, storage):
    """Delete the parts of an upload that will not complete.

    The storage keeps the parts, and the deployment pays for them, until something deletes them. A bucket
    rule deletes them after some days. This call deletes them immediately.

    Raises MultipartUploadNotFound if the upload is gone, and a StorageError for other failures.
    """
    if _is_s3_storage(storage):
        return _s3_abort_multipart_upload(storage, key, upload_id)
    _refuse(storage, "upload in parts")


# Shared by the implementations


def _refuse(storage, operation):
    # a clear error, not an AttributeError in an implementation
    raise ValueError(f"{storage.__class__.__name__} cannot {operation}")


# TODO better detection! These two compare class names, so a subclass with another name is not
# recognized.
def _is_s3_storage(storage):
    return storage.__class__.__name__ in ('S3Storage', 'S3Boto3Storage')


def _is_gcs_storage(storage):
    return storage.__class__.__name__ in ('GoogleCloudStorage', 'ZentralGoogleCloudStorage')


def _object_key(storage, key):
    """The key the storage actually holds the object under.

    With a `location` set, S3Storage and GoogleCloudStorage prefix every key they read, so a bare
    name would write — and look — outside the namespace that exists(), delete(), url() and the
    verification read all share.
    A private accessor, but it is the one url() itself uses, and there is no public equivalent: the
    paths that sign a write and the paths that read it back have to agree on one string.
    """
    from storages.utils import clean_name
    return storage._normalize_name(clean_name(key))


def _hex_to_base64(digest_hex):
    # the wire carries every digest as hex, S3 wants base64. Doing it here rather than at the call
    # site keeps "what encoding this storage wants" in one place — a caller that got it wrong would
    # sign a header the client cannot reproduce, and every upload would fail at the storage.
    try:
        return base64.b64encode(bytes.fromhex(digest_hex)).decode("ascii")
    except ValueError:
        raise ValueError(f"Not a hex digest: {digest_hex!r}")


def _base64_to_hex(digest_base64):
    # the other direction of _hex_to_base64: S3 and GCS report the digests they recorded in base64,
    # and every caller compares them against the hex the wire carries
    if not digest_base64:
        return None
    try:
        return base64.b64decode(digest_base64, validate=True).hex()
    except ValueError:
        return None


# S3


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


def _s3_presigning_client(storage):
    """A client that signs with SigV4, whatever the deployment left unset.

    botocore only presigns with SigV4 when the signature version was set EXPLICITLY. Where it is
    merely resolved from the endpoint — the default in us-east-1, and behind any custom endpoint_url
    — generate_presigned_url falls back to the legacy V2 query signature. Content-Length is then not
    signed at all, and the checksum is a query parameter S3 does not read: the storage would accept
    any body of any size, and the guarantee of generate_presigned_put() would be gone with nothing to
    see. So the version is forced here rather than trusted, on a client of the storage's own session
    so that uploads authenticate exactly like downloads.
    """
    return _s3_client(storage, "_zentral_s3_presigning_client", signature_version="s3v4")


# total_max_attempts and not max_attempts: botocore adds 1 to max_attempts, because it is a number of retries.
# The standard mode retries the throttling errors, the 5xx errors and the connection errors.
_S3_ONE_ATTEMPT = {"mode": "standard", "total_max_attempts": 1}
_S3_TASK_ATTEMPTS = {"mode": "standard", "total_max_attempts": _TASK_ATTEMPTS}

# The CompleteMultipartUpload errors that a second call cannot change
_S3_REFUSED_COMPLETION_CODES = frozenset((
    "BadDigest",              # the bytes do not agree with the declared checksum
    "EntityTooSmall",         # a part is smaller than the minimum size
    "InvalidPart",            # a part is missing, or its ETag changed
    "InvalidPartOrder",
    "InvalidRequest",         # MpuObjectSize is not the total size of the parts
))

# Do not remove. S3 validates the checksum of the completion only if CreateMultipartUpload declares the algorithm. If
# not, S3 accepts an incorrect checksum and records the checksum that it calculates: the object looks verified, but it
# is not. CRC64NVME and not SHA-256: S3 gives a full-object checksum of a multipart upload only for the CRC algorithms.
_S3_MULTIPART_CHECKSUM_ALGORITHM = "CRC64NVME"


def _s3_request_client(storage):
    """The client for the S3 calls inside a device request, with the _REQUEST limits.

    botocore sets the timeouts and the retries on the client, so each set of limits has its own client.
    Our config is merged over the config of the deployment, so the deployment cannot change these limits.
    """
    return _s3_client(storage, "_zentral_s3_request_client",
                      connect_timeout=_REQUEST_CONNECT_TIMEOUT,
                      read_timeout=_REQUEST_READ_TIMEOUT,
                      retries=_S3_ONE_ATTEMPT)


def _s3_task_client(storage):
    """The client for the S3 calls in a Celery task, with the _TASK limits."""
    return _s3_client(storage, "_zentral_s3_task_client",
                      connect_timeout=_TASK_CONNECT_TIMEOUT,
                      read_timeout=_TASK_READ_TIMEOUT,
                      retries=_S3_TASK_ATTEMPTS)


@contextmanager
def _s3_errors(refused_codes=frozenset()):
    from botocore.exceptions import BotoCoreError, ClientError, HTTPClientError
    from botocore.exceptions import ConnectionError as BotocoreConnectionError
    try:
        yield
    except (BotocoreConnectionError, HTTPClientError) as error:
        # no answer: a connection error, or a timeout
        raise StorageUnavailable(str(error)) from error
    except BotoCoreError as error:
        # a missing credential or region, or an incorrect parameter: not an outage
        raise StorageError(str(error)) from error
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "")
        status = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode") or 0
        if code == "NoSuchUpload":
            raise MultipartUploadNotFound(code) from error
        if code in refused_codes:
            raise MultipartUploadRefused(code) from error
        if code in ("SlowDown", "RequestTimeout") or status == 429 or status >= 500:
            raise StorageUnavailable(code or str(status)) from error
        raise StorageError(code or str(error)) from error


def _s3_presigned_put(storage, key, size, content_type, sha256_hex, expires_in):
    client = _s3_presigning_client(storage)
    headers = {
        "Content-Type": content_type,
        "Content-Length": str(size),
        "x-amz-checksum-sha256": _hex_to_base64(sha256_hex),
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


def _s3_presigned_get(storage, key, filename):
    return storage.url(key, parameters={"ResponseContentDisposition": f'attachment; filename="{filename}"'})


def _s3_stat_object(storage, key):
    # Two S3 details. HeadObject reports a checksum only when the request asks for it, so without
    # ChecksumMode the response is silently checksum-free and a comparison against it would pass for
    # any object at all. And a missing key surfaces as the bare status 404, not NoSuchKey — HeadObject
    # has no body to carry an error code — so an `except NoSuchKey` would never fire.
    from botocore.exceptions import ClientError
    with _s3_errors():
        try:
            response = _s3_request_client(storage).head_object(
                Bucket=storage.bucket_name, Key=_object_key(storage, key), ChecksumMode="ENABLED")
        except ClientError as error:
            if error.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 404:
                return None
            raise
    return {"size": response["ContentLength"],
            "digests": {"sha256": _base64_to_hex(response.get("ChecksumSHA256")),
                        "crc64nvme": _base64_to_hex(response.get("ChecksumCRC64NVME"))}}


def _s3_create_multipart_upload(storage, key, content_type):
    # All the multipart calls use _object_key. With a `location` set, a bare key names an object that the
    # storage does not read. ChecksumType is optional, because CRC64NVME is full-object by default.
    # ChecksumAlgorithm is necessary: see _S3_MULTIPART_CHECKSUM_ALGORITHM.
    with _s3_errors():
        response = _s3_request_client(storage).create_multipart_upload(
            Bucket=storage.bucket_name,
            Key=_object_key(storage, key),
            ContentType=content_type,
            ChecksumAlgorithm=_S3_MULTIPART_CHECKSUM_ALGORITHM,
            ChecksumType="FULL_OBJECT",
        )
    return response["UploadId"]


def _s3_presigned_part(storage, key, upload_id, part_number, size, expires_in):
    # A part has no checksum. Its only control is the Content-Length, and only a SigV4 signature includes it.
    url = _s3_presigning_client(storage).generate_presigned_url(
        "upload_part",
        Params={"Bucket": storage.bucket_name, "Key": _object_key(storage, key),
                "UploadId": upload_id, "PartNumber": part_number, "ContentLength": size},
        ExpiresIn=expires_in,
    )
    return url, {"Content-Length": str(size)}


def _s3_list_multipart_parts(storage, key, upload_id):
    # all the pages: a completion with a partial list assembles a partial object
    paginator = _s3_task_client(storage).get_paginator("list_parts")
    parts = []
    with _s3_errors():
        for page in paginator.paginate(Bucket=storage.bucket_name, Key=_object_key(storage, key),
                                       UploadId=upload_id):
            for part in page.get("Parts", ()):
                parts.append({"PartNumber": part["PartNumber"], "ETag": part["ETag"]})
    parts.sort(key=lambda part: part["PartNumber"])
    return parts


def _s3_complete_multipart_upload(storage, key, upload_id, parts, crc64nvme, object_size):
    # The caller gets the parts from the storage, never from the agent. S3 calculates the checksum of the
    # assembled object, and answers BadDigest if it is not the declared checksum.
    with _s3_errors(_S3_REFUSED_COMPLETION_CODES):
        return _s3_task_client(storage).complete_multipart_upload(
            Bucket=storage.bucket_name,
            Key=_object_key(storage, key),
            UploadId=upload_id,
            MultipartUpload={"Parts": parts},
            ChecksumCRC64NVME=_hex_to_base64(crc64nvme),
            ChecksumType="FULL_OBJECT",
            MpuObjectSize=object_size,
        )


def _s3_abort_multipart_upload(storage, key, upload_id):
    with _s3_errors():
        _s3_task_client(storage).abort_multipart_upload(
            Bucket=storage.bucket_name, Key=_object_key(storage, key), UploadId=upload_id)


# GCS


def _gcs_stat_object(storage, key):
    # get_blob() reads the metadata, not the content, and returns None for a missing object. The GCS client
    # takes the limits on each call. By default, it waits 60 seconds, and it retries for 120 seconds.
    with _gcs_errors():
        blob = storage.bucket.get_blob(_object_key(storage, key),
                                       timeout=(_REQUEST_CONNECT_TIMEOUT, _REQUEST_READ_TIMEOUT), retry=None)
    if blob is None:
        return None
    return {"size": blob.size, "digests": {"crc32c": _base64_to_hex(blob.crc32c)}}


@contextmanager
def _gcs_errors():
    from google.api_core.exceptions import GoogleAPICallError
    from google.auth.exceptions import GoogleAuthError, TransportError
    from requests.exceptions import ConnectionError as RequestsConnectionError, Timeout as RequestsTimeout
    try:
        yield
    except (RequestsConnectionError, RequestsTimeout, TransportError) as error:
        # no answer: a connection error, or a timeout
        raise StorageUnavailable(str(error)) from error
    except GoogleAuthError as error:
        # a missing or expired credential: not an outage. After TransportError, which is also a GoogleAuthError.
        raise StorageError(str(error)) from error
    except GoogleAPICallError as error:
        status = error.code or 0
        if status == 429 or status >= 500:
            raise StorageUnavailable(str(status)) from error
        raise StorageError(str(status or error)) from error

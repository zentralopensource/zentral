import base64
import hashlib
from datetime import timedelta

from django.core.files.storage import storages, InvalidStorageError


# One metadata read (a HEAD on S3, a blob GET on GCS) is a single small round trip — tens of
# milliseconds — but it happens on a device endpoint, inside the request transaction, so it gets an
# explicit ceiling instead of the minute-scale defaults of botocore and of the GCS client: an
# unbounded call to a storage that has gone quiet holds a web worker AND a database connection. One
# attempt, deliberately: a retry would double how long that transaction stays open to buy an answer
# that was never urgent, and the caller treats "could not tell" as a normal outcome, which leaves the
# upload pending. Each storage applies the ceiling in its own way: see _s3_stat_client and
# _gcs_stat_object.
_STAT_CONNECT_TIMEOUT = 2
_STAT_READ_TIMEOUT = 5


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
    raise ValueError(f"{storage.__class__.__name__} cannot presign an upload")


def stat_object(key, storage=None):
    """The stored size, and the digests of file_storage_recorded_digests() as hex.

    Returns {"size": int, "digests": {name: hex or None}}, with one entry for each recorded digest:
    None when the storage has no value of that digest for this object. Reads metadata only, never the
    object.

    Returns None when there is nothing at the key — and only then. Every other failure raises, so a
    storage that is unreachable or a key we may not read is never mistaken for an object that is not
    there.
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


# Shared by the implementations


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


def _s3_stat_client(storage):
    """A client for the S3 metadata read, with the ceiling of the _STAT constants.

    botocore binds the timeouts and the retries to a client, so the ceiling needs a client of its
    own. The deployment's config cannot lift it, because ours is merged over it.
    """
    return _s3_client(storage, "_zentral_s3_stat_client",
                      connect_timeout=_STAT_CONNECT_TIMEOUT,
                      read_timeout=_STAT_READ_TIMEOUT,
                      # one attempt. Total, not retries: botocore reads `max_attempts` as the number of
                      # RETRIES and stores max_attempts + 1, so the obvious spelling of "once" asks for
                      # twice and doubles the worst case this ceiling exists to bound.
                      # total_max_attempts is the key it keeps, and it means what it says.
                      retries={"mode": "standard", "total_max_attempts": 1})


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


def _s3_stat_object(storage, key):
    # Two S3 details. HeadObject reports a checksum only when the request asks for it, so without
    # ChecksumMode the response is silently checksum-free and a comparison against it would pass for
    # any object at all. And a missing key surfaces as the bare status 404, not NoSuchKey — HeadObject
    # has no body to carry an error code — so an `except NoSuchKey` would never fire.
    from botocore.exceptions import ClientError
    try:
        response = _s3_stat_client(storage).head_object(Bucket=storage.bucket_name,
                                                        Key=_object_key(storage, key), ChecksumMode="ENABLED")
    except ClientError as error:
        if error.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 404:
            return None
        raise
    return {"size": response["ContentLength"],
            "digests": {"sha256": _base64_to_hex(response.get("ChecksumSHA256")),
                        "crc64nvme": _base64_to_hex(response.get("ChecksumCRC64NVME"))}}


# GCS


def _gcs_stat_object(storage, key):
    # get_blob() is one GET of the JSON resource of the object: its metadata, not its content. It
    # returns None for a missing blob and raises for the rest. The GCS library takes the timeouts and
    # the retry policy on each call. Its defaults are a 60 second timeout and a retry policy with a
    # 120 second deadline: the _STAT constants replace the first, and retry=None is the one attempt.
    blob = storage.bucket.get_blob(_object_key(storage, key),
                                   timeout=(_STAT_CONNECT_TIMEOUT, _STAT_READ_TIMEOUT), retry=None)
    if blob is None:
        return None
    return {"size": blob.size, "digests": {"crc32c": _base64_to_hex(blob.crc32c)}}

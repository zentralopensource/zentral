import base64
import binascii
import hashlib

from django.core.files.storage import storages, InvalidStorageError


# One HEAD is a single small round trip — tens of milliseconds — but it happens on a device endpoint,
# inside the request transaction, so it gets an explicit ceiling instead of botocore's minute-scale
# defaults: an unbounded call to a storage that has gone quiet holds a web worker AND a database
# connection. One attempt, deliberately: a retry would double how long that transaction stays open to
# buy an answer that was never urgent, and the caller treats "could not tell" as a normal outcome it
# can ask about again later.
_STAT_CONNECT_TIMEOUT = 2
_STAT_READ_TIMEOUT = 5
# total, not retries: botocore reads `max_attempts` as the number of RETRIES and stores
# max_attempts + 1, so the obvious spelling of "once" asks for twice and doubles the worst case this
# ceiling exists to bound. total_max_attempts is the key it keeps, and it means what it says.
_STAT_TOTAL_ATTEMPTS = 1


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


def _stat_client(storage):
    """A client for the verification HEAD, with a ceiling the deployment's config cannot lift.

    Unlike the presigning client this one talks to the network, on a device endpoint, inside the
    request transaction — so an unbounded call to a storage that has gone quiet would hold a web
    worker AND a database connection. One attempt, deliberately: a retry would double how long that
    transaction stays open to buy an answer that was never urgent, and the caller treats "could not
    tell" as a normal outcome it can ask about again later.
    """
    return _s3_client(storage, "_zentral_stat_client",
                      connect_timeout=_STAT_CONNECT_TIMEOUT,
                      read_timeout=_STAT_READ_TIMEOUT,
                      retries={"mode": "standard", "total_max_attempts": _STAT_TOTAL_ATTEMPTS})


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
        client = _stat_client(storage)
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


def select_dist_storage():
    try:
        return storages["dist"]
    except InvalidStorageError:
        return storages["default"]

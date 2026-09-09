import base64
import binascii

from django.core.files.storage import storages, InvalidStorageError


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
    client = getattr(storage, "_zentral_presigning_client", None)
    if client is None:
        from botocore.client import Config
        session = storage._create_session()
        client = session.client(
            "s3",
            region_name=storage.region_name,
            use_ssl=storage.use_ssl,
            endpoint_url=storage.endpoint_url,
            verify=storage.verify,
            config=storage.client_config.merge(Config(signature_version="s3v4")),
        )
        storage._zentral_presigning_client = client
    return client


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
    from storages.utils import clean_name
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
            # through the storage's own name normalisation, not the bare key: with a `location` set,
            # S3Storage prefixes every key it reads, so a presigned PUT built from the bare name
            # would write outside the namespace that exists(), delete(), url() and the verification
            # HEAD all look in. A private name, but it is the one url() itself uses — the two paths
            # have to agree, and there is no public accessor for it.
            "Key": storage._normalize_name(clean_name(key)),
            "ContentType": content_type,
            "ContentLength": size,
            "ChecksumSHA256": headers["x-amz-checksum-sha256"],
        },
        ExpiresIn=expires_in,
    )
    return url, headers


def select_dist_storage():
    try:
        return storages["dist"]
    except InvalidStorageError:
        return storages["default"]

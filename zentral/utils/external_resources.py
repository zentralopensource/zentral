import hashlib
import os
import tempfile
from urllib.parse import urlparse
import boto3
from zentral.utils.aws import get_region as get_aws_region


def download_s3_external_resource(parsed_uri, sha256, supported_file_extensions):
    bucket = parsed_uri.netloc
    key = parsed_uri.path.lstrip("/")
    _, ext = os.path.splitext(key)
    if ext not in supported_file_extensions:
        raise ValueError(f"Unsupported file extension: '{ext}'")
    file = tempfile.NamedTemporaryFile(suffix=f".downloaded_s3_external_resource{ext}", delete=False)
    try:
        s3_client = boto3.client('s3', region_name=get_aws_region())
        s3_client.download_fileobj(bucket, key, file)
    except Exception:
        file.close()
        os.unlink(file.name)
        raise
    return file


def download_external_resource(uri, sha256, supported_file_extensions):
    parsed_uri = urlparse(uri)
    if parsed_uri.scheme == "s3":
        file = download_s3_external_resource(parsed_uri, sha256, supported_file_extensions)
    else:
        raise ValueError(f"Unknown external resource URI scheme: '{parsed_uri.scheme}'")
    # verify hash
    file.seek(0)
    h = hashlib.sha256()
    while True:
        chunk = file.read(2**10 * 64)
        if not chunk:
            break
        h.update(chunk)
    if h.hexdigest() != sha256:
        raise ValueError("Hash mismatch")
    file.seek(0)
    return os.path.basename(parsed_uri.path), file

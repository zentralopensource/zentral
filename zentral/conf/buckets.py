import logging
import os
import tempfile
from urllib.parse import urlparse


logger = logging.getLogger("zentral.conf.buckets")


class AWSBucketClient:
    platform = "AWS"

    def __init__(self):
        import boto3
        sts = boto3.client("sts")
        sts.get_caller_identity()
        self._client = boto3.client('s3')

    def download_to_tmpfile(self, key_uri):
        key_pr = urlparse(key_uri)
        bucket = key_pr.netloc
        key = key_pr.path.lstrip("/")
        if key_pr.scheme != "s3" or not bucket or not key:
            raise ValueError("Invalid S3 key URI: %s", key_uri)
        fd, filepath = tempfile.mkstemp(suffix=os.path.basename(key))
        logger.info("Download %s to %s", key_uri, filepath)
        try:
            with os.fdopen(fd, "wb") as f:
                self._client.download_fileobj(bucket, key, f)
        except Exception:
            os.unlink(filepath)
            raise
        return filepath


class GCPBucketClient:
    platform = "GCP"

    def __init__(self):
        import google.auth
        google.auth.default()
        from google.cloud import storage
        self._client = storage.Client()

    def download_to_tmpfile(self, key_uri):
        key_pr = urlparse(key_uri)
        bucket = key_pr.netloc
        key = key_pr.path.lstrip("/")
        if key_pr.scheme != "gs" or not bucket or not key:
            raise ValueError("Invalid GS key URI: %s", key_uri)
        fd, filepath = tempfile.mkstemp(suffix=os.path.basename(key))
        logger.info("Download %s to %s", key_uri, filepath)
        try:
            with os.fdopen(fd, "wb") as f:
                self._client.download_blob_to_file(key_uri, f)
        except Exception:
            os.unlink(filepath)
            raise
        return filepath


def get_bucket_client():
    for client_class in (AWSBucketClient, GCPBucketClient):
        try:
            client = client_class()
        except Exception as e:
            logger.info("Could not instantiate %s bucket client: %s",
                        client_class.platform, e)
        else:
            logger.info("%s bucket client instantiated", client.platform)
            return client
    raise RuntimeError("Cloud not instantiate bucket client")

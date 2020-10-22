import logging
import os.path
import boto3
from botocore.client import Config
from django.http import HttpResponseRedirect
from django.utils.functional import cached_property
from zentral.contrib.monolith.exceptions import RepositoryError
from zentral.utils.boto3 import make_refreshable_assume_role_session
from .base import BaseRepository


logger = logging.getLogger("zentral.contrib.monolith.repository_backends.s3")


class Repository(BaseRepository):
    def __init__(self, config):
        super().__init__(config)
        # K/V added to all the events
        self._event_extras = {}

        # bucket (required)
        self.bucket = config["bucket"]
        self._event_extras["bucket"] = self.bucket

        # bucket region (optional, can be fetched)
        self.region_name = config.get("region_name")
        if self.region_name:
            self._event_extras["region"] = self.region_name

        # relative path to the repository in the bucket (optional, default = the root of the bucket)
        self.prefix = config.get("prefix", "")
        if self.prefix:
            self._event_extras["prefix"] = self.prefix

        # fixed credentials (optional)
        self.credentials = {}
        for k in ("aws_access_key_id", "aws_secret_access_key"):
            v = config.get(k)
            if v:
                self.credentials[k] = v

        # ARN of the role to assume (optional)
        self.assume_role_arn = config.get("assume_role_arn")

        # signature version (optional, default = s3v4)
        self.signature_version = config.get("signature_version", "s3v4")

        # endpoint URL (optional, use it for special S3 like services)
        self.endpoint_url = config.get("endpoint_url")

    @cached_property
    def _session(self):
        main_session = boto3.Session(**self.credentials)
        if self.assume_role_arn:
            logger.info("Assume role %s", self.assume_role_arn)
            return make_refreshable_assume_role_session(
                main_session,
                {"RoleArn": self.assume_role_arn,
                 "RoleSessionName": "ZentralMonolithS3Repository"}
            )
        return main_session

    @cached_property
    def _client(self):
        if not self.region_name:
            # initiate a client without region first
            # to get the bucket region
            tmp_client = self._session.client("s3")
            self.region_name = tmp_client.get_bucket_location(Bucket=self.bucket)["LocationConstraint"]
            logger.info("Got bucket region %s", self.region_name)
            self._event_extras["region"] = self.region_name
        return self._session.client("s3", region_name=self.region_name, endpoint_url=self.endpoint_url,
                                    config=Config(signature_version=self.signature_version))

    def serialize_for_event(self):
        d = super().serialize_for_event()
        d.update(self._event_extras)
        return d

    def download_all_catalog(self):
        filepath = self.get_all_catalog_local_path()
        try:
            self._client.download_file(self.bucket,
                                       os.path.join(self.prefix, "catalogs/all"),
                                       filepath)
        except Exception:
            logger.exception("Could not download all catalog")
            raise RepositoryError
        return filepath

    def make_munki_repository_response(self, section, name, cache_server=None):
        # max AWS sig v4 = 7 days
        # For EC2 credentials:
        # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html
        # Last retrieved: 2020-10-22
        # "We make new credentials available at least five minutes before the expiration of the old credentials"
        expires_in = 180  # 3 minutes
        key = os.path.join(self.prefix, section, name)
        url = self._client.generate_presigned_url('get_object',
                                                  Params={'Bucket': self.bucket,
                                                          'Key': key},
                                                  ExpiresIn=expires_in)
        if cache_server:
            url = cache_server.get_cache_url(url)
        return HttpResponseRedirect(url)

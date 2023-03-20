from datetime import datetime, timedelta
import logging
import os.path
import boto3
from botocore.client import Config
from botocore.signers import CloudFrontSigner
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from django.http import HttpResponseRedirect
from django.utils.functional import cached_property
import requests
from requests.utils import requote_uri
from zentral.contrib.monolith.exceptions import RepositoryError
from zentral.utils.boto3 import make_refreshable_assume_role_session
from .base import BaseRepository


logger = logging.getLogger("zentral.contrib.monolith.repository_backends.s3")


class Repository(BaseRepository):
    def __init__(self, config):
        super().__init__(config)

        # bucket (required)
        self.bucket = config["bucket"]

        # bucket region (optional, can be fetched)
        self.region_name = config.get("region_name")

        # relative path to the repository in the bucket (optional, default = the root of the bucket)
        self.prefix = config.get("prefix", "")

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

        # cloudfront (optional)
        self.cloudfront_signer = None
        cloudfront_cfg = config.get("cloudfront")
        if not cloudfront_cfg:
            return
        self.cloudfront_domain = cloudfront_cfg.get("domain")
        if not self.cloudfront_domain:
            logger.error("Missing cloudfront domain")
            return
        key_id = cloudfront_cfg.get("key_id")
        if not key_id:
            logger.error("Missing cloudfront Key ID")
            return
        privkey_pem = cloudfront_cfg.get("privkey_pem")
        if not privkey_pem:
            logger.error("Missing cloudfront privkey PEM")
            return
        try:
            privkey = serialization.load_pem_private_key(
                privkey_pem.encode("utf-8"),
                password=None,
                backend=default_backend()
            )
        except Exception:
            logger.exception("Cloud not load cloudfront privkey")
            return

        def rsa_signer(message):
            return privkey.sign(message, padding.PKCS1v15(), hashes.SHA1())

        self.cloudfront_signer = CloudFrontSigner(key_id, rsa_signer)

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
            # unauthenticated request to get the bucket region
            resp = requests.head("https://s3.amazonaws.com", headers={"Host": f"{self.bucket}.s3.amazonaws.com"})
            self.region_name = resp.headers["x-amz-bucket-region"]
            logger.info("Got bucket region %s", self.region_name)
        return self._session.client("s3", region_name=self.region_name, endpoint_url=self.endpoint_url,
                                    config=Config(signature_version=self.signature_version))

    def get_all_catalog_content(self):
        try:
            return self._client.get_object(
                Bucket=self.bucket,
                Key=os.path.join(self.prefix, "catalogs/all")
            )['Body'].read()
        except Exception:
            logger.exception("Could not download all catalog")
            raise RepositoryError

    def make_munki_repository_response(self, section, name, cache_server=None):
        expires_in = 180  # 3 minutes
        key = os.path.join(self.prefix, section, name)
        if self.cloudfront_signer:
            url = self.cloudfront_signer.generate_presigned_url(
                requote_uri(f"https://{self.cloudfront_domain}/{key}"),
                date_less_than=datetime.utcnow() + timedelta(seconds=expires_in)
            )
        else:
            # max AWS sig v4 = 7 days
            # For EC2 credentials:
            # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html
            # Last retrieved: 2020-10-22
            # "We make new credentials available at least five minutes before the expiration of the old credentials"
            url = self._client.generate_presigned_url('get_object',
                                                      Params={'Bucket': self.bucket,
                                                              'Key': key},
                                                      ExpiresIn=expires_in)
            if cache_server:
                url = cache_server.get_cache_url(url)
        return HttpResponseRedirect(url)

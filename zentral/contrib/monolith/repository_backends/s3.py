from datetime import datetime, timedelta
import logging
import os.path
import boto3
from botocore.client import Config
from botocore.signers import CloudFrontSigner
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from django import forms
from django.http import HttpResponseRedirect
from django.utils.functional import cached_property
import requests
from requests.utils import requote_uri
from rest_framework import serializers
from zentral.contrib.monolith.exceptions import RepositoryError
from zentral.utils.boto3 import make_refreshable_assume_role_session
from .base import BaseRepository


logger = logging.getLogger("zentral.contrib.monolith.repository_backends.s3")


def load_cloudfront_private_key(privkey_pem):
    return serialization.load_pem_private_key(
        privkey_pem.encode("utf-8"),
        password=None,
    )


class S3RepositoryForm(forms.Form):
    bucket = forms.CharField()
    region_name = forms.CharField(required=False)
    prefix = forms.CharField(required=False)
    access_key_id = forms.CharField(required=False)
    secret_access_key = forms.CharField(required=False)
    assume_role_arn = forms.CharField(label="Assume role ARN", required=False)
    signature_version = forms.CharField(required=False)
    endpoint_url = forms.URLField(label="Endpoint URL", required=False, assume_scheme="https")
    cloudfront_domain = forms.CharField(required=False)
    cloudfront_key_id = forms.CharField(required=False)
    cloudfront_privkey_pem = forms.CharField(widget=forms.Textarea, required=False)

    def clean_cloudfront_privkey_pem(self):
        data = self.cleaned_data.get("cloudfront_privkey_pem")
        if data:
            try:
                load_cloudfront_private_key(data)
            except Exception:
                raise forms.ValidationError("Invalid private key.")
        return data

    def clean(self):
        cleaned_data = super().clean()
        # cloudfront
        cf_domain = cleaned_data.get("cloudfront_domain")
        cf_key_id = cleaned_data.get("cloudfront_key_id")
        cf_privkey_pem = cleaned_data.get("cloudfront_privkey_pem")
        if cf_domain or cf_key_id or cf_privkey_pem:
            err_msg = "This field is required when configuring Cloudfront."
            if not cf_domain:
                self.add_error("cloudfront_domain", err_msg)
            if not cf_key_id:
                self.add_error("cloudfront_key_id", err_msg)
            if not cf_privkey_pem and "cloudfront_privkey_pem" not in self.errors:
                self.add_error("cloudfront_privkey_pem", err_msg)

    def get_backend_kwargs(self):
        return {k: v for k, v in self.cleaned_data.items() if v}


class S3RepositorySerializer(serializers.Serializer):
    bucket = serializers.CharField()
    region_name = serializers.CharField(required=False, allow_blank=True)
    prefix = serializers.CharField(required=False, allow_blank=True)
    access_key_id = serializers.CharField(required=False, allow_blank=True)
    secret_access_key = serializers.CharField(required=False, allow_blank=True)
    assume_role_arn = serializers.CharField(required=False, allow_blank=True)
    signature_version = serializers.CharField(required=False, allow_blank=True)
    endpoint_url = serializers.URLField(required=False, allow_blank=True)
    cloudfront_domain = serializers.CharField(required=False, allow_blank=True)
    cloudfront_key_id = serializers.CharField(required=False, allow_blank=True)
    cloudfront_privkey_pem = serializers.CharField(required=False, allow_blank=True)

    def validate_cloudfront_privkey_pem(self, value):
        if value:
            try:
                load_cloudfront_private_key(value)
            except Exception:
                raise serializers.ValidationError("Invalid private key.")
        return value

    def validate(self, data):
        data = super().validate(data)
        # cloudfront
        cf_domain = data.get("cloudfront_domain")
        cf_key_id = data.get("cloudfront_key_id")
        cf_privkey_pem = data.get("cloudfront_privkey_pem")
        cf_errors = {}
        if cf_domain or cf_key_id or cf_privkey_pem:
            err_msg = "This field is required when configuring Cloudfront."
            if not cf_domain:
                cf_errors.update({"cloudfront_domain": err_msg})
            if not cf_key_id:
                cf_errors.update({"cloudfront_key_id": err_msg})
            if not cf_privkey_pem:
                cf_errors.update({"cloudfront_privkey_pem": err_msg})
        if cf_errors:
            raise serializers.ValidationError(cf_errors)
        return data


class S3Repository(BaseRepository):
    kwargs_keys = (
        "bucket",
        "region_name",
        "prefix",
        "access_key_id",
        "secret_access_key",
        "assume_role_arn",
        "signature_version",
        "endpoint_url",
        "cloudfront_domain",
        "cloudfront_key_id",
        "cloudfront_privkey_pem"
    )
    encrypted_kwargs_keys = (
        "cloudfront_privkey_pem",
        "secret_access_key"
    )
    form_class = S3RepositoryForm

    def load(self):
        super().load()

        # default prefix
        if not self.prefix:
            self.prefix = ""

        # fixed credentials (optional)
        self.credentials = {}
        for ck, k in (("aws_access_key_id", "access_key_id"),
                      ("aws_secret_access_key", "secret_access_key")):
            v = getattr(self, k)
            if v:
                self.credentials[ck] = v

        # signature version
        if not self.signature_version:
            self.signature_version = "s3v4"

        # cloudfront signer (optional)
        self.cloudfront_signer = None
        if not self.cloudfront_domain:
            return
        try:
            privkey = load_cloudfront_private_key(self.cloudfront_privkey_pem)
        except Exception:
            logger.exception("Cloud not load cloudfront privkey")
            return

        def rsa_signer(message):
            return privkey.sign(message, padding.PKCS1v15(), hashes.SHA1())

        self.cloudfront_signer = CloudFrontSigner(self.cloudfront_key_id, rsa_signer)

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

    def _get_resource(self, key, missing_ok=False):
        try:
            return self._client.get_object(
                Bucket=self.bucket,
                Key=os.path.join(self.prefix, key)
            )['Body'].read()
        except self._client.exceptions.NoSuchKey:
            logging_args = ("Could not find key %s in repository %s", key, self.repository)
            if missing_ok:
                logger.info(*logging_args)
                return None
            logger.exception(*logging_args)
            raise RepositoryError(logging_args[0] % logging_args[1:])
        except Exception as e:
            logger.exception("Could not download key %s in repository %s", key, self.repository)
            raise RepositoryError(str(e))

    def get_all_catalog_content(self):
        return self._get_resource("catalogs/all")

    def get_icon_hashes_content(self):
        return self._get_resource("icons/_icon_hashes.plist", missing_ok=True)

    def iter_client_resources(self):
        prefix = os.path.join(self.prefix, "client_resources/")
        try:
            paginator = self._client.get_paginator('list_objects_v2')
            for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    yield obj["Key"].removeprefix(prefix)
        except Exception as e:
            logger.exception("Could not list client resources keys in repository %s", self.repository)
            raise RepositoryError(str(e))

    def make_munki_repository_response(self, section, name, cache_server=None):
        expires_in = 180  # 3 minutes TODO: hardcoded
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

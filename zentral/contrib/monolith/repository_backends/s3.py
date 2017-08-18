import os.path
import boto3
from botocore.client import Config
from django.http import HttpResponseRedirect
from zentral.contrib.monolith.exceptions import RepositoryError
from .base import BaseRepository


class Repository(BaseRepository):
    def __init__(self, config):
        super().__init__(config)
        self.aws_access_key_id = config["aws_access_key_id"]
        self.aws_secret_access_key = config["aws_secret_access_key"]
        self.signature_version = config.get("signature_version", None)
        self.bucket = config["bucket"]
        self.config = {}
        for attr in ("signature_version", "region_name"):
            val = config.get(attr, None)
            if val:
                self.config[attr] = val
        self.prefix = config.get("prefix", "")
        self._client = None

    def serialize_for_event(self):
        d = super().serialize_for_event()
        for attr in ("region_name", "bucket"):
            val = self.config.get(attr)
            if val:
                d[attr] = val
        if self.prefix:
            d["prefix"] = self.prefix
        return d

    @property
    def client(self):
        if self._client is None:
            config = None
            if self.config:
                config = Config(**self.config)
            self._client = boto3.client('s3',
                                        aws_access_key_id=self.aws_access_key_id,
                                        aws_secret_access_key=self.aws_secret_access_key,
                                        config=config)
        return self._client

    def download_all_catalog(self):
        filepath = self.get_all_catalog_local_path()
        try:
            self.client.download_file(self.bucket,
                                      os.path.join(self.prefix, "catalogs/all"),
                                      filepath)
        except Exception as e:
            print("Exception", e)
            raise RepositoryError
        return filepath

    def make_munki_repository_response(self, section, name, cache_server=None):
        expires_in = 600  # 10 minutes, max AWS sig v4 = 7 days
        key = os.path.join(self.prefix, section, name)
        url = self.client.generate_presigned_url('get_object',
                                                 Params={'Bucket': self.bucket,
                                                         'Key': key},
                                                 ExpiresIn=expires_in)
        if cache_server:
            url = cache_server.get_cache_url(url)
        return HttpResponseRedirect(url)

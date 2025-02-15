import base64
import boto3
from botocore.config import Config
from django.utils.functional import cached_property
from .base import BaseSecretEngine


class SecretEngine(BaseSecretEngine):
    def __init__(self, config_d):
        super().__init__(config_d)
        # key
        self.key_id = config_d["key_id"]

        # client config
        self.client_kwargs = {
            "config": Config(
                retries={
                    "max_attempts": 3,
                    "mode": "standard"
                }
            )
        }
        if self.key_id.startswith("arn:"):
            self.client_kwargs["region_name"] = self.key_id.split(":")[3]
        for kwarg in ("region_name",
                      "endpoint_url",
                      "aws_access_key_id",
                      "aws_secret_access_key",
                      "aws_session_token"):
            if kwarg in self.client_kwargs:
                continue
            val = config_d.get(kwarg)
            if val:
                self.client_kwargs[kwarg] = val

    @cached_property
    def kms_client(self):
        return boto3.client("kms", **self.client_kwargs)

    def _prepared_context(self, context):
        prepared_context = {}
        for k, v in context.items():
            if not isinstance(v, str):
                v = str(v)
            prepared_context[k] = v
        for k, v in self.default_context.items():
            if k not in prepared_context:
                prepared_context[k] = v
        return prepared_context

    def encrypt(self, data, **context):
        response = self.kms_client.encrypt(
            KeyId=self.key_id,
            Plaintext=data,
            EncryptionContext=self._prepared_context(context),
            EncryptionAlgorithm='SYMMETRIC_DEFAULT'
        )
        return base64.urlsafe_b64encode(response['CiphertextBlob']).decode("utf-8")

    def decrypt(self, data, **context):
        response = self.kms_client.decrypt(
            KeyId=self.key_id,
            CiphertextBlob=base64.urlsafe_b64decode(data.encode("utf-8")),
            EncryptionContext=self._prepared_context(context),
            EncryptionAlgorithm='SYMMETRIC_DEFAULT'
        )
        return response['Plaintext']

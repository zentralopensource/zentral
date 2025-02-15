import base64
import json
from django.utils.functional import cached_property
from google.cloud import kms
from google.oauth2 import service_account
import google_crc32c
from .base import BaseSecretEngine


class SecretEngine(BaseSecretEngine):
    def __init__(self, config_d):
        super().__init__(config_d)
        self.key_name = kms.KeyManagementServiceClient.crypto_key_path(
            config_d["project_id"],
            config_d["location_id"],
            config_d["key_ring_id"],
            config_d["key_id"]
        )
        self.credentials_file = config_d.get("credentials")

    @cached_property
    def kms_client(self):
        # credentials
        credentials = None
        if self.credentials_file:
            credentials = service_account.Credentials.from_service_account_file(self.credentials_file)
            credentials = credentials.with_scopes(["https://www.googleapis.com/auth/cloudkms"])
        return kms.KeyManagementServiceClient(credentials=credentials)

    @staticmethod
    def _crc32c(data):
        return google_crc32c.value(data)

    def _prepared_context(self, context):
        prepared_context = {}
        for k, v in context.items():
            if not isinstance(v, str):
                v = str(v)
            prepared_context[k] = v
        for k, v in self.default_context.items():
            if k not in prepared_context:
                prepared_context[k] = v
        return json.dumps(prepared_context, ensure_ascii=False, sort_keys=True).encode("utf-8")

    def encrypt(self, data, **context):
        additional_authenticated_data = self._prepared_context(context)
        response = self.kms_client.encrypt(request={
            "name": self.key_name,
            "plaintext": data,
            "plaintext_crc32c": self._crc32c(data),
            "additional_authenticated_data": additional_authenticated_data,
            "additional_authenticated_data_crc32c": self._crc32c(additional_authenticated_data),
        })
        if not response.verified_plaintext_crc32c or not response.verified_additional_authenticated_data_crc32c:
            raise Exception("The request sent to the server was corrupted in-transit.")
        if not response.ciphertext_crc32c == self._crc32c(response.ciphertext):
            raise Exception("The response received from the server was corrupted in-transit.")
        return base64.urlsafe_b64encode(response.ciphertext).decode("utf-8")

    def decrypt(self, data, **context):
        ciphertext = base64.urlsafe_b64decode(data.encode("utf-8"))
        additional_authenticated_data = self._prepared_context(context)
        response = self.kms_client.decrypt(request={
            "name": self.key_name,
            "ciphertext": ciphertext,
            "ciphertext_crc32c": self._crc32c(ciphertext),
            "additional_authenticated_data": additional_authenticated_data,
            "additional_authenticated_data_crc32c": self._crc32c(additional_authenticated_data),
        })
        if not response.plaintext_crc32c == self._crc32c(response.plaintext):
            raise Exception("The response received from the server was corrupted in-transit.")
        return response.plaintext

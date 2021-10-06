import base64
from .base import BaseSecretEngine


class SecretEngine(BaseSecretEngine):
    def encrypt(self, data, **context):
        return base64.urlsafe_b64encode(data).decode("utf-8")

    def decrypt(self, data, **context):
        return base64.urlsafe_b64decode(data.encode("utf-8"))

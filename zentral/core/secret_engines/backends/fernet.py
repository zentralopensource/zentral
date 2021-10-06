import base64
from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.conf import settings
from .base import BaseSecretEngine


class SecretEngine(BaseSecretEngine):
    kd_iterations = 100000

    def __init__(self, config_d):
        super().__init__(config_d)
        salt = settings.SECRET_KEY.encode("utf-8")
        fernets = []
        for password in config_d["passwords"]:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=self.kd_iterations
            )
            fernets.append(Fernet(base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))))
        self._multifernet = MultiFernet(fernets)

    def encrypt(self, data, **context):
        return self._multifernet.encrypt(data).decode("utf-8")

    def decrypt(self, data, **context):
        return self._multifernet.decrypt(data.encode("utf-8"))

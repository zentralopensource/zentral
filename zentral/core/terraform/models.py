import logging
import zlib
from cryptography.fernet import Fernet
from django.db import models
from accounts.models import User
from zentral.core.secret_engines import decrypt, encrypt, rewrap
from zentral.utils.ssl import ensure_bytes


logger = logging.getLogger('zentral.core.terraform.models')


class State(models.Model):
    slug = models.SlugField(unique=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, editable=False)
    created_by_username = models.TextField(editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.slug


class StateVersion(models.Model):
    state = models.ForeignKey(State, on_delete=models.CASCADE)
    encryption_key = models.TextField(default="")
    data = models.BinaryField(null=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, editable=False)
    created_by_username = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.state} - {self.created_at}"

    # secret - encryption key

    def _get_secret_engine_kwargs(self, field):
        if not self.pk:
            raise ValueError("StateVersion must have a pk")
        return {"pk": self.pk, "model": "terraform.stateversion", "field": field}

    def get_encryption_key(self):
        return decrypt(self.encryption_key, **self._get_secret_engine_kwargs("encryption_key"))

    def set_encryption_key(self, encryption_key):
        self.encryption_key = encrypt(encryption_key, **self._get_secret_engine_kwargs("encryption_key"))

    def rewrap_secrets(self):
        self.encryption_key = rewrap(self.encryption_key, **self._get_secret_engine_kwargs("encryption_key"))

    # data - Terraform state

    # We use the encrypted encryption key to encrypt the state.
    # We cannot use the secret engine directly, because of the potential limitations on the size.
    # We also compress the state before encryption.

    def get_data(self):
        f = Fernet(self.get_encryption_key())
        return zlib.decompress(f.decrypt(ensure_bytes(self.data)))

    def set_data(self, data):
        encryption_key = Fernet.generate_key()
        self.set_encryption_key(encryption_key)
        f = Fernet(encryption_key)
        self.data = f.encrypt(zlib.compress(data, level=9))


class Lock(models.Model):
    state = models.OneToOneField(State, on_delete=models.CASCADE, primary_key=True)
    uid = models.CharField(max_length=256)
    info = models.JSONField()
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, editable=False)
    created_by_username = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.uid

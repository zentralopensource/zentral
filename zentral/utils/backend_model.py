from functools import partial
import hashlib
from django.db import models
from zentral.core.secret_engines import decrypt, decrypt_str, encrypt_str, rewrap


class Backend:
    kwargs_keys = ()
    encrypted_kwargs_paths = ()

    def __init__(self, instance, load=True):
        self.instance = instance
        self.name = instance.name
        self.kwargs = {}
        if load:
            self.load()

    def __str__(self):
        return self.name

    def load(self):
        kwargs = self.get_kwargs()
        for key in self.kwargs_keys:
            setattr(self, key, kwargs.get(key))

    def _get_secret_engine_kwargs(self, path):
        if not self.instance.pk:
            raise ValueError("Backend instance must have a primary key")
        return {"field": ".".join(path),
                "model": f"{self.instance._meta.app_label}.{self.instance._meta.model_name}",
                "pk": str(self.instance.pk)}

    def _iter_kwargs(self, func, root, enc_path=None, path=None, enc_path_suffix=""):
        if enc_path is None:
            enc_path = []
        if path is None:
            path = []
        if isinstance(root, dict):
            new_root = {}
            for k, v in root.items():
                next_enc_path = enc_path + [k]
                next_path = path + [k]
                if (
                    enc_path_suffix and
                    (next_enc_path in self.encrypted_kwargs_paths
                     or isinstance(v, list) and next_enc_path + ["*"] in self.encrypted_kwargs_paths)
                ):
                    k = f"{k}{enc_path_suffix}"
                new_root[k] = self._iter_kwargs(func, v, next_enc_path, next_path, enc_path_suffix)
            root = new_root
        elif isinstance(root, list):
            root = [self._iter_kwargs(func, v, enc_path + ["*"], path + [str(i)], enc_path_suffix)
                    for i, v in enumerate(root)]
        else:
            if root is not None and enc_path in self.encrypted_kwargs_paths:
                root = func(root, **self._get_secret_engine_kwargs(path))
        return root

    def get_kwargs(self):
        return self._iter_kwargs(decrypt_str, self.instance.backend_kwargs)

    def set_kwargs(self, kwargs):
        self.instance.backend_kwargs = self._iter_kwargs(encrypt_str, kwargs)

    def rewrap_kwargs(self):
        self.instance.backend_kwargs = self._iter_kwargs(rewrap, self.instance.backend_kwargs)

    def get_kwargs_for_event(self):

        def hash_secret(v, **secret_engine_kwargs):
            return hashlib.sha256(decrypt(v, **secret_engine_kwargs)).hexdigest()

        return self._iter_kwargs(hash_secret, self.instance.backend_kwargs, enc_path_suffix="_hash")


class BackendInstance(models.Model):
    name = models.CharField(unique=True)
    description = models.TextField(blank=True)
    backend_kwargs = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

    def __str__(self):
        return self.name

    def get_backend_kwargs(self):
        backend = self.get_backend()
        return backend.get_kwargs()

    def get_backend_kwargs_for_event(self):
        backend = self.get_backend()
        return backend.get_kwargs_for_event()

    def set_backend_kwargs(self, kwargs):
        backend = self.get_backend()
        backend.set_kwargs(kwargs)

    def rewrap_secrets(self):
        backend = self.get_backend()
        backend.rewrap_kwargs()

    def serialize_for_event(self, keys_only=False):
        d = {
            "pk": str(self.pk),
            "name": self.name,
        }
        if not keys_only:
            d.update({
                "backend": str(self.backend),
                "backend_kwargs": self.get_backend_kwargs_for_event(),
                "description": self.description,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
            })
        return d

    def _get_BACKEND_kwargs(self, backend):
        if self.backend == backend:
            return self.get_backend_kwargs()

    def __getattr__(self, name):
        for backend in self.backend_enum:
            if name == f"get_{backend.lower()}_kwargs":
                return partial(self._get_BACKEND_kwargs, backend)
        raise AttributeError

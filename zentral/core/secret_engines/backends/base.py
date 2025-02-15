from zentral.conf.config import ConfigDict
from zentral.core.exceptions import ImproperlyConfigured


class BaseSecretEngine:
    def __init__(self, config_d):
        self.name = config_d['secret_engine_name']
        self.default = config_d.get("default", False)
        # default context
        default_context = config_d.get("default_context") or {}
        if isinstance(default_context, ConfigDict):
            default_context = default_context.serialize()
        if not isinstance(default_context, dict):
            raise ImproperlyConfigured("Default context is not a dict")
        for key, val in default_context.items():
            if not isinstance(key, str) or not isinstance(val, str):
                raise ImproperlyConfigured("Default context is not a dict[str, str]")
        self.default_context = default_context

    def encrypt(self, data, **context):
        raise NotImplementedError

    def decrypt(self, data, **context):
        raise NotImplementedError

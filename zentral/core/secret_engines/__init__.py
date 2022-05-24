from collections import OrderedDict
from importlib import import_module
import logging
from django.utils.functional import SimpleLazyObject
from zentral.conf import settings

logger = logging.getLogger('zentral.core.secret_engines')


class SecretEngines:
    separator = "$"
    noop_engine_name = "noop"
    noop_engine_backend = "zentral.core.secret_engines.backends.cleartext"

    @staticmethod
    def _get_secret_engine_class(module_path):
        class_name = "SecretEngine"
        module = import_module(module_path)
        return getattr(module, class_name)

    def load_config(self, config):
        self.secret_engines = OrderedDict()
        self.default_secret_engine = None
        # add configured engines
        for secret_engine_name, secret_engine_conf in config.items():
            if secret_engine_name == self.noop_engine_name:
                self.logger.error("'%s' is a reserved engine name. skipped!", self.noop_engine_name)
                continue
            if self.separator in secret_engine_name:
                self.logger.error("'%' not allowed in secret engine name. skipped!", self.separator)
                continue
            secret_engine_conf = secret_engine_conf.copy()
            secret_engine_conf['secret_engine_name'] = secret_engine_name
            secret_engine_class = self._get_secret_engine_class(secret_engine_conf.pop('backend'))
            secret_engine = secret_engine_class(secret_engine_conf)
            self.secret_engines[secret_engine_name] = secret_engine
            if secret_engine.default:
                if self.default_secret_engine:
                    logger.error('Multiple default secret engines')
                else:
                    self.default_secret_engine = secret_engine
        # add noop engine
        noop_secret_engine_class = self._get_secret_engine_class(self.noop_engine_backend)
        noop_secret_engine = noop_secret_engine_class({'secret_engine_name': self.noop_engine_name})
        self.secret_engines[self.noop_engine_name] = noop_secret_engine
        # default default secret engine
        if not self.default_secret_engine:
            logger.info("No default secret engine")
            for secret_engine_name, secret_engine in self.secret_engines.items():
                logger.info("Use '%s' secret engine as default", secret_engine_name)  # noqa lgtm[py/clear-text-logging-sensitive-data]
                self.default_secret_engine = secret_engine
                break

    def __init__(self, settings):
        self.load_config(settings.get("secret_engines", {}))

    def __len__(self):
        return len(self.secret_engines)

    def get(self, secret_engine_name):
        return self.secret_engines.get(secret_engine_name)


secret_engines = SimpleLazyObject(lambda: SecretEngines(settings))


class EncryptionError(Exception):
    pass


class DecryptionError(Exception):
    pass


def encrypt(data, **context):
    if not isinstance(data, bytes):
        raise TypeError("a bytes object is required")
    default_secret_engine = secret_engines.default_secret_engine
    try:
        encoded_data = default_secret_engine.encrypt(data, **context)
    except Exception as exc:
        raise EncryptionError(f"Secret engine {default_secret_engine.name} encryption error") from exc
    return "{}${}".format(default_secret_engine.name, encoded_data)


def encrypt_str(data, **context):
    if not isinstance(data, str):
        raise TypeError("a str object is required")
    return encrypt(data.encode("utf-8"), **context)


def decrypt(token, **context):
    try:
        secret_engine_name, data = token.split("$")
    except ValueError:
        raise DecryptionError("Bad token structure")
    secret_engine = secret_engines.get(secret_engine_name)
    if not secret_engine:
        raise DecryptionError(f"Unknown secret engine: '{secret_engine_name}'")
    try:
        return secret_engine.decrypt(data, **context)
    except Exception as exc:
        raise DecryptionError("Secret engine decryption error") from exc


def decrypt_str(token, **context):
    return decrypt(token, **context).decode("utf-8")


def rewrap(token, **context):
    return encrypt(decrypt(token, **context), **context)

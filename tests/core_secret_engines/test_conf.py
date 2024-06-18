from django.test import TestCase
from zentral.core.secret_engines import secret_engines
from zentral.core.secret_engines.backends.cleartext import SecretEngine as ClearTextSecretEngine


class SecretEnginesConfTestCase(TestCase):
    def test_default_secret_engine(self):
        default_secret_engine = secret_engines.default_secret_engine
        self.assertEqual(default_secret_engine.name, "noop")
        self.assertEqual(len(secret_engines), 1)
        self.assertEqual(secret_engines.get("noop"), default_secret_engine)
        self.assertTrue(isinstance(secret_engines.get("noop"), ClearTextSecretEngine))

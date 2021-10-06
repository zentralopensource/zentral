from django.test import TestCase
from zentral.core.secret_engines import decrypt, decrypt_str, encrypt, encrypt_str, rewrap


class ClearTextSecretEngineTestCase(TestCase):
    def test_encrypt_default_noop_secret_engine(self):
        self.assertEqual(encrypt(b"le temps des cerises", yolo=1, fomo=2),
                         "noop$bGUgdGVtcHMgZGVzIGNlcmlzZXM=")

    def test_encrypt_str_default_noop_secret_engine(self):
        self.assertEqual(encrypt_str("le temps des cerises", yolo=1, fomo=2),
                         "noop$bGUgdGVtcHMgZGVzIGNlcmlzZXM=")

    def test_decrypt_default_noop_secret_engine(self):
        self.assertEqual(decrypt("noop$bGUgdGVtcHMgZGVzIGNlcmlzZXM=", yolo=1, fomo=2),
                         b"le temps des cerises")

    def test_decrypt_str_default_noop_secret_engine(self):
        self.assertEqual(decrypt_str("noop$bGUgdGVtcHMgZGVzIGNlcmlzZXM=", yolo=1, fomo=2),
                         "le temps des cerises")

    def test_rewrap_default_noop_secret_engine(self):
        token = "noop$bGUgdGVtcHMgZGVzIGNlcmlzZXM="
        # rewrap is a noop for this secret engine
        self.assertEqual(rewrap(token, yolo=1, fomo=2), token)

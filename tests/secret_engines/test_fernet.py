from django.test import SimpleTestCase
from zentral.core.secret_engines import (decrypt, decrypt_str, encrypt, encrypt_str, rewrap,
                                         secret_engines, DecryptionError)


class FernetSecretEngineTestCase(SimpleTestCase):
    def test_encrypt_decrypt_simple(self):
        secret_engines.load_config({
            "fernet": {"backend": "zentral.core.secret_engines.backends.fernet",
                       "passwords": ["undeuxtrois"]}
        })
        self.assertEqual(decrypt(encrypt(b"le temps des cerises", yolo=1), yolo=1),
                         b"le temps des cerises")
        secret_engines.load_config({})

    def test_encrypt_str_decrypt_str_simple(self):
        secret_engines.load_config({
            "fernet": {"backend": "zentral.core.secret_engines.backends.fernet",
                       "passwords": ["undeuxtrois"]}
        })
        self.assertEqual(decrypt_str(encrypt_str("le temps des cerises", yolo=1), yolo=1),
                         "le temps des cerises")
        secret_engines.load_config({})

    def test_encrype_decrypt_rotation_same_engine(self):
        # encrypt with first password
        secret_engines.load_config({
            "fernet": {"backend": "zentral.core.secret_engines.backends.fernet",
                       "passwords": ["undeuxtrois"]}
        })
        token = encrypt(b"le temps des cerises", yolo=1)
        # add new password
        secret_engines.load_config({
            "fernet": {"backend": "zentral.core.secret_engines.backends.fernet",
                       "passwords": ["quatrecinqsix", "undeuxtrois"]}
        })
        new_token = rewrap(token, yolo=1)
        # remove old password, new password can decrypt
        secret_engines.load_config({
            "fernet": {"backend": "zentral.core.secret_engines.backends.fernet",
                       "passwords": ["quatrecinqsix"]}
        })
        self.assertEqual(decrypt(new_token, yolo=1), b"le temps des cerises")
        # old password cannot decrypt
        secret_engines.load_config({
            "fernet": {"backend": "zentral.core.secret_engines.backends.fernet",
                       "passwords": ["undeuxtrois"]}
        })
        with self.assertRaises(DecryptionError):
            decrypt(new_token, yolo=1)
        # default config
        secret_engines.load_config({})

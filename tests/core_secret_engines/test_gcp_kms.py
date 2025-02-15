from unittest.mock import patch, Mock
from django.test import SimpleTestCase
from zentral.conf.config import ConfigDict
from zentral.core.exceptions import ImproperlyConfigured
from zentral.core.secret_engines import (decrypt_str, encrypt_str, secret_engines,
                                         DecryptionError, EncryptionError)
from zentral.core.secret_engines.backends.gcp_kms import SecretEngine


class GCPKMSSecretEngineTestCase(SimpleTestCase):
    def test_init(self):
        secret_engines.load_config(ConfigDict({
            "gcp": {"backend": "zentral.core.secret_engines.backends.gcp_kms",
                    "project_id": "PROJECT_ID",
                    "location_id": "LOCATION",
                    "key_ring_id": "KEY_RING",
                    "key_id": "KEY_NAME",
                    "default_context": {"un": "1"}}
        }))
        secret_engine = secret_engines.default_secret_engine
        self.assertIsInstance(secret_engine, SecretEngine)
        self.assertEqual(
            secret_engine.key_name,
            "projects/PROJECT_ID/locations/LOCATION/keyRings/KEY_RING/cryptoKeys/KEY_NAME"
        )
        self.assertEqual(secret_engine.default_context, {"un": "1"})
        self.assertIsNone(secret_engine.credentials_file)

    def test_init_default_context_not_a_dict(self):
        with self.assertRaises(ImproperlyConfigured) as cm:
            secret_engines.load_config({
                "gcp": {"backend": "zentral.core.secret_engines.backends.gcp_kms",
                        "project_id": "PROJECT_ID",
                        "location_id": "LOCATION",
                        "key_ring_id": "KEY_RING",
                        "key_id": "KEY_NAME",
                        "default_context": "un"}
            })
        self.assertEqual(cm.exception.args[0], "Default context is not a dict")

    def test_init_default_context_not_a_dict_str_str(self):
        with self.assertRaises(ImproperlyConfigured) as cm:
            secret_engines.load_config({
                "gcp": {"backend": "zentral.core.secret_engines.backends.gcp_kms",
                        "project_id": "PROJECT_ID",
                        "location_id": "LOCATION",
                        "key_ring_id": "KEY_RING",
                        "key_id": "KEY_NAME",
                        "default_context": {"un": 1}}
            })
        self.assertEqual(cm.exception.args[0], "Default context is not a dict[str, str]")

    def test_prepared_context(self):
        secret_engines.load_config(ConfigDict({
            "gcp": {"backend": "zentral.core.secret_engines.backends.gcp_kms",
                    "project_id": "PROJECT_ID",
                    "location_id": "LOCATION",
                    "key_ring_id": "KEY_RING",
                    "key_id": "KEY_NAME",
                    "default_context": {"un": "1"}}
        }))
        secret_engine = secret_engines.default_secret_engine
        self.assertEqual(
            secret_engine._prepared_context({"un": "0", "deux": 2}),
            b'{"deux": "2", "un": "0"}'
        )

    @patch("zentral.core.secret_engines.backends.gcp_kms.kms.KeyManagementServiceClient")
    def test_encrypt_str_corrupted_request(self, gcp_client):
        mocked_response = Mock()
        mocked_response.verified_plaintext_crc32c = True
        mocked_response.verified_additional_authenticated_data_crc32c = False
        mocked_response.ciphertext = b"fomo"
        mocked_response.ciphertext_crc32c = 3847521259
        mocked_client = Mock()
        mocked_client.encrypt.return_value = mocked_response
        gcp_client.return_value = mocked_client
        secret_engines.load_config({
            "gcp": {"backend": "zentral.core.secret_engines.backends.gcp_kms",
                    "project_id": "PROJECT_ID",
                    "location_id": "LOCATION",
                    "key_ring_id": "KEY_RING",
                    "key_id": "KEY_NAME",
                    "default_context": {"un": "1"}}
        })
        with self.assertRaises(EncryptionError) as cm:
            encrypt_str("yolo")
        self.assertEqual(
            cm.exception.__context__.args[0],
            "The request sent to the server was corrupted in-transit."
        )

    @patch("zentral.core.secret_engines.backends.gcp_kms.kms.KeyManagementServiceClient")
    def test_encrypt_str_corrupted_response(self, gcp_client):
        mocked_response = Mock()
        mocked_response.verified_plaintext_crc32c = True
        mocked_response.verified_additional_authenticated_data_crc32c = True
        mocked_response.ciphertext = b"fomo"
        mocked_response.ciphertext_crc32c = 0  # not 3847521259
        mocked_client = Mock()
        mocked_client.encrypt.return_value = mocked_response
        gcp_client.return_value = mocked_client
        secret_engines.load_config({
            "gcp": {"backend": "zentral.core.secret_engines.backends.gcp_kms",
                    "project_id": "PROJECT_ID",
                    "location_id": "LOCATION",
                    "key_ring_id": "KEY_RING",
                    "key_id": "KEY_NAME",
                    "default_context": {"un": "1"}}
        })
        with self.assertRaises(EncryptionError) as cm:
            encrypt_str("yolo")
        self.assertEqual(
            cm.exception.__context__.args[0],
            "The response received from the server was corrupted in-transit."
        )

    @patch("zentral.core.secret_engines.backends.gcp_kms.kms.KeyManagementServiceClient")
    def test_encrypt_str(self, gcp_client):
        mocked_response = Mock()
        mocked_response.verified_plaintext_crc32c = True
        mocked_response.verified_additional_authenticated_data_crc32c = True
        mocked_response.ciphertext = b"fomo"
        mocked_response.ciphertext_crc32c = 3847521259
        mocked_client = Mock()
        mocked_client.encrypt.return_value = mocked_response
        gcp_client.return_value = mocked_client
        secret_engines.load_config({
            "gcp": {"backend": "zentral.core.secret_engines.backends.gcp_kms",
                    "project_id": "PROJECT_ID",
                    "location_id": "LOCATION",
                    "key_ring_id": "KEY_RING",
                    "key_id": "KEY_NAME",
                    "default_context": {"un": "1"}}
        })
        self.assertEqual(encrypt_str("yolo"), "gcp$Zm9tbw==")

    @patch("zentral.core.secret_engines.backends.gcp_kms.kms.KeyManagementServiceClient")
    def test_decrypt_str_corrupted_response(self, gcp_client):
        mocked_response = Mock()
        mocked_response.plaintext = b"yolo"
        mocked_response.plaintext_crc32c = 0  # not 4040585613
        mocked_client = Mock()
        mocked_client.decrypt.return_value = mocked_response
        gcp_client.return_value = mocked_client
        secret_engines.load_config({
            "gcp": {"backend": "zentral.core.secret_engines.backends.gcp_kms",
                    "project_id": "PROJECT_ID",
                    "location_id": "LOCATION",
                    "key_ring_id": "KEY_RING",
                    "key_id": "KEY_NAME",
                    "default_context": {"un": "1"}}
        })
        with self.assertRaises(DecryptionError) as cm:
            decrypt_str("gcp$Zm9tbw==")
        self.assertEqual(
            cm.exception.__context__.args[0],
            "The response received from the server was corrupted in-transit."
        )

    @patch("zentral.core.secret_engines.backends.gcp_kms.kms.KeyManagementServiceClient")
    def test_decrypt_str(self, gcp_client):
        mocked_response = Mock()
        mocked_response.plaintext = b"yolo"
        mocked_response.plaintext_crc32c = 4040585613
        mocked_client = Mock()
        mocked_client.decrypt.return_value = mocked_response
        gcp_client.return_value = mocked_client
        secret_engines.load_config({
            "gcp": {"backend": "zentral.core.secret_engines.backends.gcp_kms",
                    "project_id": "PROJECT_ID",
                    "location_id": "LOCATION",
                    "key_ring_id": "KEY_RING",
                    "key_id": "KEY_NAME",
                    "default_context": {"un": "1"}}
        })
        self.assertEqual(decrypt_str("gcp$Zm9tbw=="), "yolo")
        mocked_client.decrypt.assert_called_once()

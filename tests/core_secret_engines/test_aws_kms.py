from unittest.mock import patch, Mock
from django.test import SimpleTestCase
from zentral.conf.config import ConfigDict
from zentral.core.exceptions import ImproperlyConfigured
from zentral.core.secret_engines import decrypt_str, encrypt_str, secret_engines
from zentral.core.secret_engines.backends.aws_kms import SecretEngine


class AWSKMSSecretEngineTestCase(SimpleTestCase):
    def test_init_key_id_uuid(self):
        secret_engines.load_config(ConfigDict({
            "aws": {"backend": "zentral.core.secret_engines.backends.aws_kms",
                    "key_id": "8ee44b97-8475-475c-bb1e-ac9198b2451d",
                    "region_name": "us-east-1",
                    "default_context": {"un": "1"}}
        }))
        secret_engine = secret_engines.default_secret_engine
        self.assertIsInstance(secret_engine, SecretEngine)
        self.assertEqual(secret_engine.client_kwargs["region_name"], "us-east-1")
        self.assertEqual(secret_engine.default_context, {"un": "1"})

    def test_init_key_id_arn(self):
        secret_engines.load_config({
            "aws": {"backend": "zentral.core.secret_engines.backends.aws_kms",
                    "key_id": "arn:aws:kms:eu-central-1:000000000000:key/8ee44b97-8475-475c-bb1e-ac9198b2451d",
                    "region_name": "us-east-1"}  # ignored
        })
        secret_engine = secret_engines.default_secret_engine
        self.assertIsInstance(secret_engine, SecretEngine)
        self.assertEqual(secret_engine.client_kwargs["region_name"], "eu-central-1")
        self.assertEqual(secret_engine.default_context, {})

    def test_init_default_context_not_a_dict(self):
        with self.assertRaises(ImproperlyConfigured) as cm:
            secret_engines.load_config({
                "aws": {"backend": "zentral.core.secret_engines.backends.aws_kms",
                        "key_id": "8ee44b97-8475-475c-bb1e-ac9198b2451d",
                        "region_name": "us-east-1",
                        "default_context": "un"}
            })
        self.assertEqual(cm.exception.args[0], "Default context is not a dict")

    def test_init_default_context_not_a_dict_str_str(self):
        with self.assertRaises(ImproperlyConfigured) as cm:
            secret_engines.load_config({
                "aws": {"backend": "zentral.core.secret_engines.backends.aws_kms",
                        "key_id": "8ee44b97-8475-475c-bb1e-ac9198b2451d",
                        "region_name": "us-east-1",
                        "default_context": {"un": 1}}
            })
        self.assertEqual(cm.exception.args[0], "Default context is not a dict[str, str]")

    def test_prepared_context(self):
        secret_engines.load_config(ConfigDict({
            "aws": {"backend": "zentral.core.secret_engines.backends.aws_kms",
                    "key_id": "8ee44b97-8475-475c-bb1e-ac9198b2451d",
                    "region_name": "us-east-1",
                    "default_context": {"un": "1"}}
        }))
        secret_engine = secret_engines.default_secret_engine
        self.assertEqual(
            secret_engine._prepared_context({"un": "0", "deux": 2}),
            {"un": "0", "deux": "2"}
        )

    @patch("zentral.core.secret_engines.backends.aws_kms.boto3.client")
    def test_encrypt_str(self, boto3_client):
        mocked_client = Mock()
        mocked_client.encrypt.return_value = {"CiphertextBlob": b"fomo"}
        boto3_client.return_value = mocked_client
        secret_engines.load_config({
            "aws": {"backend": "zentral.core.secret_engines.backends.aws_kms",
                    "key_id": "8ee44b97-8475-475c-bb1e-ac9198b2451d",
                    "region_name": "us-east-1",
                    "default_context": {"un": "1"}}
        })
        self.assertEqual(encrypt_str("yolo"), "aws$Zm9tbw==")
        mocked_client.encrypt.assert_called_once_with(
            KeyId="8ee44b97-8475-475c-bb1e-ac9198b2451d",
            Plaintext=b"yolo",
            EncryptionContext={"un": "1"},
            EncryptionAlgorithm='SYMMETRIC_DEFAULT'
        )

    @patch("zentral.core.secret_engines.backends.aws_kms.boto3.client")
    def test_decrypt_str(self, boto3_client):
        mocked_client = Mock()
        mocked_client.decrypt.return_value = {"Plaintext": b"yolo"}
        boto3_client.return_value = mocked_client
        secret_engines.load_config({
            "aws": {"backend": "zentral.core.secret_engines.backends.aws_kms",
                    "key_id": "arn:aws:kms:eu-central-1:000000000000:key/8ee44b97-8475-475c-bb1e-ac9198b2451d"}
        })
        self.assertEqual(decrypt_str("aws$Zm9tbw=="), "yolo")
        mocked_client.decrypt.assert_called_once_with(
            KeyId="arn:aws:kms:eu-central-1:000000000000:key/8ee44b97-8475-475c-bb1e-ac9198b2451d",
            CiphertextBlob=b"fomo",
            EncryptionContext={},
            EncryptionAlgorithm='SYMMETRIC_DEFAULT'
        )

import os
import shutil
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import SimpleTestCase
from zentral.utils.osx_package import BasePackageBuilder
from .packages import DummyPackageBuilder


class OSXPackageBuilderTestCase(SimpleTestCase):
    def _dummy_builder(self, name="test123", version="1.0", product_archive_title=None):
        builder = DummyPackageBuilder(name, version, product_archive_title)
        self.addCleanup(builder.cleanup)
        self.addCleanup(shutil.rmtree, builder.tempdir, True)
        return builder

    def test_get_signature_size(self):
        builder = BasePackageBuilder()
        self.addCleanup(builder._clean)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_path = os.path.join(builder.tempdir, "signing.key")
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        # a RSA-2048 signature is the size of the modulus, 256 bytes
        self.assertEqual(builder._get_signature_size(key_path), 256)

    def test_builder_defaults(self):
        builder = self._dummy_builder()
        self.assertIsNone(builder.get_extra_installcheck_script())
        self.assertEqual(builder.get_extra_packages(), [])
        self.assertIsNone(builder.get_etag())
        self.assertIsNone(builder.get_last_modified_dt())

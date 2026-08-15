import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import SimpleTestCase
from zentral.utils.osx_package import BasePackageBuilder


class OSXPackageBuilderTestCase(SimpleTestCase):
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

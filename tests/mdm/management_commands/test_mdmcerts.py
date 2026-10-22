import datetime
import os
import tempfile
import shutil
from io import StringIO
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from zentral.contrib.mdm.management.commands.mdmcerts import Command


class MDMManagementCommandMDMCertsTest(TestCase):

    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as tmpdirname:
            cls.dir_name = tmpdirname

    @classmethod
    def tearDownClass(cls):
        dir_exist = os.path.exists(cls.dir_name)
        if dir_exist:
            shutil.rmtree(cls.dir_name)

    # utils

    def call_command(self, *args, **kwargs):
        stdout = StringIO()
        stderr = StringIO()
        call_command(
            "mdmcerts",
            *args,
            stdout=stdout,
            stderr=stderr,
            **kwargs,
        )
        return stdout.getvalue(), stderr.getvalue()

    @staticmethod
    def build_self_signed_certificate(key, common_name):
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        return x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
        ).sign(key, hashes.SHA256())

    # mdmcerts

    def test_mdmcerts_default(self):
        with self.assertRaises(CommandError):
            stdout, stderr = self.call_command()
            self.assertIn("usage:", stdout)
            self.assertIn("the following arguments are required: subcommand", stderr)

    @patch("zentral.contrib.mdm.management.commands.mdmcerts.requests.get")
    @patch("zentral.contrib.mdm.management.commands.mdmcerts.getpass")
    def test_mdmcerts_2_steps(self, getpass, requests_get):
        # Create MDM vendor CSR
        getpass.getpass.return_value = 'password'

        stdout, stderr = self.call_command('-d', self.dir_name, 'init')

        self.assertIn(f"MDM certificates dir {self.dir_name}", stderr)
        self.assertIn(f"Create Vendor CSR {self.dir_name}/vendor.csr OK", stderr)

        # Skip CSR signature. We generate the vendor.crt ourselves for the tests
        # 1) load private key
        with open(os.path.join(self.dir_name, "vendor.key"), "rb") as kf:
            key = serialization.load_pem_private_key(kf.read(), password="password".encode("utf-8"))
        # 2) generate self-signed certificate
        cert = self.build_self_signed_certificate(key, "self-signed")
        with open(os.path.join(self.dir_name, "vendor.crt"), "wb") as vf:
            vf.write(cert.public_bytes(serialization.Encoding.DER))

        # Self-signed stand-ins for the Apple certificates the command downloads
        apple_certs = {
            Command.apple_int_url: self.build_self_signed_certificate(key, "Apple WWDR CA G3"),
            Command.apple_root_url: self.build_self_signed_certificate(key, "Apple Root CA"),
        }
        requests_get.side_effect = lambda url: Mock(content=apple_certs[url].public_bytes(serialization.Encoding.DER))

        # Create a push certificate CSR signed with (mocked) vendor certificate
        stdout, stderr = self.call_command('-d', self.dir_name, 'req', 'DE')
        self.assertIn("Create Push CSR", stderr)
        self.assertIn("Sign Push CSR", stderr)
        self.assertIn("Save Push REQ", stderr)

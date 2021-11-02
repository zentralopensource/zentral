import base64
import getpass
import os
import plistlib
import requests
import string
import subprocess
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'MDM certificates helper'
    apple_int_url = "https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer"
    apple_root_url = "https://www.apple.com/appleca/AppleIncRootCertificate.cer"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._dir = None

    def add_arguments(self, parser):
        parser.add_argument("-d", "--dir", default="mdm_certificates")
        subparsers = parser.add_subparsers(title="subcommands", dest="subcommand", required=True)
        parser_i = subparsers.add_parser("init",
                                         called_from_command_line=True,
                                         help="Initialize the MDM certificates dir")
        parser_i.set_defaults(func=self.do_init)
        parser_r = subparsers.add_parser("req",
                                         called_from_command_line=True,
                                         help="Create a MDM push certificate request")
        parser_r.set_defaults(func=self.do_req)
        parser_r.add_argument("-p", "--prefix", default="", help="MDM push certificate files prefix")
        # The country in the CSR is reflected in the Push certificate, but not much else

        def a_country(country):
            if len(country) != 2 or any(lt not in string.ascii_letters for lt in country):
                raise ValueError
            return country.upper()
        parser_r.add_argument("country", type=a_country, help="MDM push certificate country")

    def handle(self, *args, **options):
        self._dir = options.pop("dir")
        options["func"](**options)

    def _get_vendor_private_key_password(self):
        return getpass.getpass("Vendor private key password? ")

    def _init_working_dir(self):
        if not os.path.isdir(self._dir):
            self.stderr.write(f"Create MDM certificates dir {self._dir}")
            os.makedirs(self._dir)
        else:
            self.stderr.write(f"MDM certificates dir {self._dir} OK")

    def _vendor_key_path(self):
        return os.path.join(self._dir, "vendor.key")

    def _vendor_csr_path(self):
        return os.path.join(self._dir, "vendor.csr")

    def _vendor_crt_path(self):
        return os.path.join(self._dir, "vendor.crt")

    def _create_vendor_csr(self):
        csr_path = self._vendor_csr_path()
        self.stderr.write(f"Create Vendor CSR {csr_path}", ending=" ")
        pwd = self._get_vendor_private_key_password()
        env = os.environ.copy()
        env["ZENTRAL_MDMCERTS_VPKP"] = pwd
        subprocess.run([
            "openssl", "req",
            "-newkey", "rsa:2048",
            "-passout", "env:ZENTRAL_MDMCERTS_VPKP",
            "-keyout", self._vendor_key_path(),
            "-subj", "/CN=MDM Vendor",
            "-out", csr_path
        ], env=env, stderr=subprocess.DEVNULL)
        self.stderr.write("OK")

    def do_init(self, **options):
        self._init_working_dir()
        self._create_vendor_csr()

    def _build_vendor_fullchain(self):
        certs = []

        def append_der_cert(data):
            cert = x509.load_der_x509_certificate(data)
            certs.append(cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"))

        with open(self._vendor_crt_path(), "rb") as f:
            append_der_cert(f.read())
        for url in (self.apple_int_url, self.apple_root_url):
            r = requests.get(url)
            append_der_cert(r.content)
        return "\n".join(c.strip() for c in certs)

    def _push_csr_path(self, prefix):
        return os.path.join(self._dir, f"{prefix}push.csr")

    def _get_push_private_key_password(self):
        return getpass.getpass("Push private key password? ")

    def _push_key_path(self, prefix):
        return os.path.join(self._dir, f"{prefix}push.key")

    def _create_push_csr(self, prefix, country):
        csr_path = self._push_csr_path(prefix)
        self.stderr.write(f"Create Push CSR {csr_path}", ending=" ")
        pwd = self._get_push_private_key_password()
        env = os.environ.copy()
        env["ZENTRAL_MDMCERTS_PPKP"] = pwd
        subprocess.run([
            "openssl", "req",
            "-newkey", "rsa:2048",
            "-passout", "env:ZENTRAL_MDMCERTS_PPKP",
            "-keyout", self._push_key_path(prefix),
            "-subj", f"/CN=MDM Push/C={country}",
            "-outform", "der",
            "-out", csr_path
        ], env=env, stderr=subprocess.DEVNULL)
        with open(csr_path, "rb") as f:
            b64_csr = base64.b64encode(f.read()).decode("utf-8")
        self.stderr.write("OK")
        return b64_csr

    def _sign_push_csr(self, prefix):
        csr_path = self._push_csr_path(prefix)
        self.stderr.write(f"Sign Push CSR {csr_path}", ending=" ")
        pwd = self._get_vendor_private_key_password()
        env = os.environ.copy()
        env["ZENTRAL_MDMCERTS_VPKP"] = pwd
        cp = subprocess.run([
            "openssl", "dgst",
            "-sha256",
            "-sign", self._vendor_key_path(),
            "-passin", "env:ZENTRAL_MDMCERTS_VPKP",
            csr_path
        ], env=env, capture_output=True)
        signature = base64.b64encode(cp.stdout).decode("utf-8")
        self.stderr.write("OK")
        return signature

    def _write_push_req(self, prefix, fullchain, b64_csr, b64_signature):
        req_path = os.path.join(self._dir, f"{prefix}push.req")
        self.stderr.write(f"Save Push REQ {req_path}", ending=" ")
        payload = {
            "PushCertCertificateChain": fullchain,
            "PushCertRequestCSR": b64_csr,
            "PushCertSignature": b64_signature
        }
        with open(req_path, "wb") as f:
            f.write(base64.b64encode(plistlib.dumps(payload)))
        self.stderr.write("OK")

    def do_req(self, **options):
        prefix = options["prefix"]
        self._init_working_dir()
        fullchain = self._build_vendor_fullchain()
        b64_csr = self._create_push_csr(prefix, options["country"])
        b64_signature = self._sign_push_csr(prefix)
        self._write_push_req(prefix, fullchain, b64_csr, b64_signature)

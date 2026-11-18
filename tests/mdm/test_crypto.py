import os.path
import plistlib
from datetime import datetime
from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID
from django.test import SimpleTestCase
from zentral.contrib.mdm.crypto import verify_iphone_ca_signed_payload, verify_signed_payload
from .utils import build_signed_data_with_unknown_signer, build_signed_data_without_signer


class MDMCryptoTestCase(SimpleTestCase):
    def test_verify_iphone_ca_signed_payload(self):
        with open(
            os.path.join(os.path.dirname(__file__), "testdata/ota_playload_phase_2"),
            "rb",
        ) as f:
            signed_payload = f.read()
        payload = verify_iphone_ca_signed_payload(signed_payload)
        self.assertEqual(
            plistlib.loads(payload),
            {
                "CHALLENGE": "8gLEIttrT7qbLOZs3XzL5XPgNXCliGwRLtn2Lfe4GBsa7g6MGm2sJjicKrLFal4D",
                "IMEI": "",
                "MEID": "",
                "NotOnConsole": False,
                "PRODUCT": "VirtualMac2,1",
                "SERIAL": "ZDL2M9PTJ3",
                "UDID": "78897E40-F532-5DE0-A7DC-56BAC5CEEB9C",
                "UserID": "D9DD912C-1B1E-413F-86A5-3BE29F13AB2D",
                "UserLongName": "admin",
                "UserShortName": "admin",
                "VERSION": "22A380",
            },
        )

    def test_verify_signed_payload_without_signer(self):
        with self.assertRaises(ValueError) as cm:
            verify_signed_payload(build_signed_data_without_signer(b"yolo"))
        self.assertEqual(str(cm.exception), "No signer")

    def test_verify_detached_signature_without_signer(self):
        with self.assertRaises(ValueError) as cm:
            verify_signed_payload(b"yolo", build_signed_data_without_signer())
        self.assertEqual(str(cm.exception), "No signer")

    def test_verify_signed_payload_unknown_signer_certificate(self):
        with self.assertRaises(ValueError) as cm:
            verify_signed_payload(build_signed_data_with_unknown_signer(b"yolo"))
        self.assertEqual(str(cm.exception), "Signer certificate not found")

    def test_verify_signed_payload_subject_key_identifier(self):
        with self.assertRaises(ValueError) as cm:
            verify_signed_payload(build_signed_data_with_unknown_signer(b"yolo", subject_key_identifier=True))
        self.assertEqual(str(cm.exception), "Unsupported signer identifier: subject_key_identifier")


class MDMCryptoSignedAttributesTestCase(SimpleTestCase):
    payload = b"yolo"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "yolo")])
        cls.cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .not_valid_before(datetime(2025, 1, 1))
            .not_valid_after(datetime(2035, 1, 1))
            .serial_number(x509.random_serial_number())
            .public_key(cls.key.public_key())
            .sign(private_key=cls.key, algorithm=hashes.SHA256())
        )

    def sign(self, detached=False):
        options = [pkcs7.PKCS7Options.Binary]
        if detached:
            options.append(pkcs7.PKCS7Options.DetachedSignature)
        return (
            pkcs7.PKCS7SignatureBuilder()
            .set_data(self.payload)
            .add_signer(self.cert, self.key, hashes.SHA256())
            .sign(serialization.Encoding.DER, options)
        )

    def update_signed_attrs(self, signed_data, update):
        content_info = cms.ContentInfo.load(signed_data)
        signer = content_info["content"]["signer_infos"][0]
        signer["signed_attrs"] = update(list(signer["signed_attrs"]))
        return content_info.dump(force=True)

    def assertNotVerified(self, message, payload, detached_signature=None):
        with self.assertRaises(ValueError) as cm:
            verify_signed_payload(payload, detached_signature)
        self.assertEqual(str(cm.exception), message)

    def test_signed_attributes(self):
        signed_data = self.sign()
        signer = cms.ContentInfo.load(signed_data)["content"]["signer_infos"][0]
        self.assertEqual({attr["type"].native for attr in signer["signed_attrs"]},
                         {"content_type", "signing_time", "smime_capabilities", "message_digest"})
        certificates, payload = verify_signed_payload(signed_data)
        self.assertEqual([certificate for _, _, certificate in certificates], [self.cert])
        self.assertEqual(payload, self.payload)

    def test_detached_signed_attributes(self):
        certificates, payload = verify_signed_payload(self.payload, self.sign(detached=True))
        self.assertEqual(len(certificates), 1)
        self.assertEqual(payload, self.payload)

    def test_swapped_content(self):
        content_info = cms.ContentInfo.load(self.sign())
        content_info["content"]["encap_content_info"]["content"] = b"fomo"
        self.assertNotVerified("Message digest mismatch", content_info.dump(force=True))

    def test_swapped_detached_content(self):
        self.assertNotVerified("Message digest mismatch", b"fomo", self.sign(detached=True))

    def test_missing_content(self):
        content_info = cms.ContentInfo.load(self.sign())
        content_info["content"]["encap_content_info"]["content"] = None
        self.assertNotVerified("No content", content_info.dump(force=True))

    def test_missing_message_digest(self):
        signed_data = self.update_signed_attrs(
            self.sign(),
            lambda attrs: [attr for attr in attrs if attr["type"].native != "message_digest"]
        )
        self.assertNotVerified("Missing message digest", signed_data)

    def test_multiple_message_digests(self):
        signed_data = self.update_signed_attrs(
            self.sign(),
            lambda attrs: attrs + [cms.CMSAttribute({"type": "message_digest", "values": [b"fomo"]})]
        )
        self.assertNotVerified("Multiple message_digest signed attributes", signed_data)

    def test_content_type_mismatch(self):
        signed_data = self.update_signed_attrs(
            self.sign(),
            lambda attrs: [
                cms.CMSAttribute({"type": "content_type", "values": ["signed_data"]})
                if attr["type"].native == "content_type" else attr
                for attr in attrs
            ]
        )
        self.assertNotVerified("Content type mismatch", signed_data)

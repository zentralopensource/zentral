import os.path
import plistlib
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

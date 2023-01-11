import os.path
import plistlib
from django.test import SimpleTestCase
from zentral.contrib.mdm.crypto import verify_iphone_ca_signed_payload


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

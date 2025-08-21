from unittest import TestCase
from zentral.contrib.inventory.conf import mac_secure_enclave_from_model


class MacSecureEnclaveTestCase(TestCase):
    def test_ok(self):
        for model, secure_enclave in (
            # No secure enclave
            ("Macmini3,1", None),
            # T1
            ("MacBookPro13,3", "T1"),
            # T2
            ("iMac20,1", "T2"),
            ("MacBookPro16,2", "T2"),
            # SILICON
            ("iMac21,2", "SILICON"),
            ("Mac16,12", "SILICON"),
            ("MacBookAir10,1", "SILICON"),
            ("MacBookPro17,1", "SILICON"),
            ("Macmini9,1", "SILICON"),
            # Bad
            (None, None),
            ("NOT_A_MATCH", None),
        ):
            self.assertEqual(mac_secure_enclave_from_model(model), secure_enclave)

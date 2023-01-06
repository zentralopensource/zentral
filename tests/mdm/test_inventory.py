import os.path
import plistlib
from django.test import SimpleTestCase
from zentral.contrib.mdm.inventory import ms_tree_from_payload


class MDMInventoryTestCase(SimpleTestCase):
    def test_ms_tree_from_payload(self):
        device_information = plistlib.load(
            open(os.path.join(os.path.dirname(__file__),
                              "testdata/device_information.plist"),
                 "rb")
        )
        ms_tree = ms_tree_from_payload(device_information["QueryResponses"])
        self.assertEqual(ms_tree["system_info"]["computer_name"], "Yolo")
        self.assertEqual(ms_tree["system_info"]["hardware_model"], "VirtualMac2,1")
        self.assertEqual(ms_tree["os_version"]["name"], "macOS")
        self.assertEqual(ms_tree["os_version"]["major"], 13)
        self.assertEqual(ms_tree["os_version"]["minor"], 0)
        self.assertEqual(ms_tree["os_version"]["patch"], 0)

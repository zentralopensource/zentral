import plistlib
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.mdm.inventory import commit_tree_from_payload
from zentral.contrib.inventory.models import MetaBusinessUnit, MetaMachine
from .utils import force_dep_enrollment_session


device_information = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CommandUUID</key>
  <string>02CD8B7A-465F-49E6-86D6-D3ACAAE5529E</string>
  <key>QueryResponses</key>
  <dict>
    <key>ActiveManagedUsers</key>
    <array>
      <string>5DF1182E-C70B-4A3A-BADC-DD3E775040FB</string>
    </array>
    <key>AutoSetupAdminAccounts</key>
    <array/>
    <key>AvailableDeviceCapacity</key>
    <real>10.0</real>
    <key>AwaitingConfiguration</key>
    <false/>
    <key>BluetoothMAC</key>
    <string>00:00:00:00:00:00</string>
    <key>BuildVersion</key>
    <string>22A5321d</string>
    <key>CurrentConsoleManagedUser</key>
    <string>5DF1182E-C70B-4A3A-BADC-DD3E775040FB</string>
    <key>DeviceCapacity</key>
    <real>29.0</real>
    <key>DeviceName</key>
    <string>Yolo</string>
    <key>EthernetMAC</key>
    <string>22:7a:00:00:00:00</string>
    <key>HostName</key>
    <string>Yolo.local</string>
    <key>IsActivationLockEnabled</key>
    <false/>
    <key>IsActivationLockSupported</key>
    <true/>
    <key>IsAppleSilicon</key>
    <true/>
    <key>IsSupervised</key>
    <true/>
    <key>LocalHostName</key>
    <string>Yolo</string>
    <key>MDMOptions</key>
    <dict/>
    <key>Model</key>
    <string>VirtualMac2,1</string>
    <key>ModelName</key>
    <string>Virtual Machine</string>
    <key>OSUpdateSettings</key>
    <dict>
      <key>AutoCheckEnabled</key>
      <true/>
      <key>AutomaticAppInstallationEnabled</key>
      <false/>
      <key>AutomaticOSInstallationEnabled</key>
      <false/>
      <key>AutomaticSecurityUpdatesEnabled</key>
      <true/>
      <key>BackgroundDownloadEnabled</key>
      <true/>
      <key>CatalogURL</key>
      <string>https://swscan.apple.com/content/catalogs/others/index-TOOLONG.merged-1.sucatalog.gz</string>
      <key>IsDefaultCatalog</key>
      <true/>
      <key>PreviousScanDate</key>
      <date>2022-09-09T08:38:04Z</date>
      <key>PreviousScanResult</key>
      <integer>2</integer>
    </dict>
    <key>OSVersion</key>
    <string>13.0</string>
    <key>OSXSoftwareUpdateStatus</key>
    <dict>
      <key>AutoCheckEnabled</key>
      <true/>
      <key>AutomaticAppInstallationEnabled</key>
      <false/>
      <key>AutomaticOSInstallationEnabled</key>
      <false/>
      <key>AutomaticSecurityUpdatesEnabled</key>
      <true/>
      <key>BackgroundDownloadEnabled</key>
      <true/>
      <key>CatalogURL</key>
      <string>https://swscan.apple.com/content/catalogs/others/index-TOOLONG.merged-1.sucatalog.gz</string>
      <key>IsDefaultCatalog</key>
      <true/>
      <key>PreviousScanDate</key>
      <date>2022-09-09T08:38:04Z</date>
      <key>PreviousScanResult</key>
      <integer>2</integer>
    </dict>
    <key>PINRequiredForDeviceLock</key>
    <true/>
    <key>PINRequiredForEraseDevice</key>
    <false/>
    <key>ProductName</key>
    <string>VirtualMac2,1</string>
    <key>ProvisioningUDID</key>
    <string>00000000-0000000000000000</string>
    <key>SerialNumber</key>
    <string>Z3C2FCE2C0</string>
    <key>SoftwareUpdateDeviceID</key>
    <string>VMA2MACOSAP</string>
    <key>SupportsLOMDevice</key>
    <false/>
    <key>SupportsiOSAppInstalls</key>
    <true/>
    <key>SystemIntegrityProtectionEnabled</key>
    <false/>
    <key>UDID</key>
    <string>9353BC9A-5CF9-4C9E-9AD4-8D1E41D5FE3E</string>
    <key>XsanConfiguration</key>
    <dict>
      <key>role</key>
      <string>unconfigured</string>
    </dict>
    <key>iTunesStoreAccountIsActive</key>
    <false/>
  </dict>
  <key>Status</key>
  <string>Acknowledged</string>
  <key>UDID</key>
  <string>9353BC9A-5CF9-4C9E-9AD4-8D1E41D5FE3E</string>
</dict>
</plist>"""


class MDMInventoryTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()

    def test_payload(self):
        _, device_udid, serial_number = force_dep_enrollment_session(self.mbu, completed=True)
        payload = plistlib.loads(device_information.encode("utf-8"))["QueryResponses"]
        tree = commit_tree_from_payload(device_udid, serial_number, self.mbu, payload)
        self.assertEqual(tree["serial_number"], serial_number)
        mm = MetaMachine(serial_number)
        self.assertEqual(len(mm.snapshots), 1)
        ms = mm.snapshots[0]
        self.assertEqual(ms.source.name, "MDM")
        system_info = ms.system_info
        self.assertEqual(system_info.computer_name, "Yolo")
        self.assertEqual(system_info.hardware_model, "VirtualMac2,1")
        os_version = ms.os_version
        self.assertEqual(os_version.name, "macOS")
        self.assertEqual(os_version.major, 13)
        self.assertEqual(os_version.minor, 0)
        self.assertEqual(os_version.patch, 0)

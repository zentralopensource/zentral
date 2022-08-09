import copy
from datetime import date
from unittest.mock import patch, Mock
from django.core.management import call_command
from django.test import TestCase
from zentral.contrib.mdm.models import SoftwareUpdate, SoftwareUpdateDeviceID
from zentral.contrib.mdm.software_updates import sync_software_updates


fake_response = {
    "PublicAssetSets": {
        "iOS": [
            {"ProductVersion": "12.5.5",
             "PostingDate": "2022-07-28",
             "ExpirationDate": "2022-11-06",
             "SupportedDevices": [
                 "iPad4,1",
                 "iPod7,1"
             ]},
            {"ProductVersion": "15.6",
             "PostingDate": "2022-07-28",
             "ExpirationDate": "2022-11-06",
             "SupportedDevices": [
                 "iPad11,1",
                 "iPad11,2",
             ]},
        ],
        "macOS": [
            {"ProductVersion": "11.6.8",
             "PostingDate": "2022-07-28",
             "ExpirationDate": "2022-11-06",
             "SupportedDevices": [
                 "J780AP",
                 "Mac-06F11F11946D27C5",
             ]},
        ]
    },
    "AssetSets": {
        "macOS": [
            {"ProductVersion": "12.5",
             "PostingDate": "2022-07-20",
             "SupportedDevices": [
                 "J132AP",
             ]},
        ]
    }
}


class MDMSoftwareUpdateTestCase(TestCase):
    @patch("zentral.contrib.mdm.software_updates.requests.get")
    def test_sync_software_update(self, get):
        response_json = Mock()
        response_json.return_value = fake_response
        response = Mock()
        response.json = response_json
        get.return_value = response
        sync_software_updates()
        self.assertEqual(SoftwareUpdate.objects.count(), 4)
        self.assertEqual(SoftwareUpdateDeviceID.objects.count(), 7)
        self.assertEqual(SoftwareUpdate.objects.filter(public=True).count(), 3)
        self.assertEqual(SoftwareUpdate.objects.filter(public=False).count(), 1)
        psu = SoftwareUpdate.objects.filter(public=False).first()
        self.assertEqual(psu.platform, "macOS")
        self.assertEqual(psu.major, 12)
        self.assertEqual(psu.minor, 5)
        self.assertEqual(psu.patch, 0)
        self.assertEqual(list(psudi.device_id for psudi in psu.softwareupdatedeviceid_set.all()), ["J132AP"])
        self.assertEqual(psu.posting_date, date(2022, 7, 20))
        self.assertIsNone(psu.expiration_date)

    @patch("zentral.contrib.mdm.software_updates.requests.get")
    def test_sync_software_update_update(self, get):
        response_json = Mock()
        response_json.return_value = fake_response
        response = Mock()
        response.json = response_json
        get.return_value = response
        sync_software_updates()
        fake_response2 = copy.deepcopy(fake_response)
        # add one / remove one device id
        supported_device = fake_response2["PublicAssetSets"]["iOS"][0]["SupportedDevices"]
        self.assertEqual(supported_device.pop(), "iPod7,1")
        supported_device.append("iPad4,2")
        self.assertEqual(
            set(
                sudi.device_id for sudi in SoftwareUpdateDeviceID.objects.filter(
                    software_update__platform="iOS",
                    software_update__public=True,
                    software_update__major=12,
                    software_update__minor=5,
                    software_update__patch=5
                )
            ),
            {"iPad4,1", "iPod7,1"}
        )
        # replace one software update
        fake_response2["AssetSets"]["macOS"][0]["ProductVersion"] = "12.4"
        self.assertEqual(SoftwareUpdate.objects.filter(public=False, major=12, minor=5).count(), 1)
        self.assertEqual(SoftwareUpdate.objects.filter(public=False, major=12, minor=4).count(), 0)
        # re-run sync with updated response
        response_json.return_value = fake_response2
        sync_software_updates()
        # check updated device ids
        self.assertEqual(
            set(
                sudi.device_id for sudi in SoftwareUpdateDeviceID.objects.filter(
                    software_update__platform="iOS",
                    software_update__public=True,
                    software_update__major=12,
                    software_update__minor=5,
                    software_update__patch=5
                )
            ),
            {"iPad4,1", "iPad4,2"}
        )
        # check replaced software update
        self.assertEqual(SoftwareUpdate.objects.filter(public=False, major=12, minor=5).count(), 0)
        self.assertEqual(SoftwareUpdate.objects.filter(public=False, major=12, minor=4).count(), 1)

    @patch("zentral.contrib.mdm.software_updates.requests.get")
    def test_management_command(self, get):
        response_json = Mock()
        response_json.return_value = fake_response
        response = Mock()
        response.json = response_json
        get.return_value = response
        call_command('sync_software_updates')
        response_json.assert_called_once_with()
        self.assertEqual(SoftwareUpdate.objects.count(), 4)
        self.assertEqual(SoftwareUpdateDeviceID.objects.count(), 7)

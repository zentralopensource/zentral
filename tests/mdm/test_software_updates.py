import copy
import json
import os.path
import datetime
from psycopg2.extras import DateRange
from unittest.mock import patch, Mock
from django.core.management import call_command
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.models import SoftwareUpdate, SoftwareUpdateDeviceID
from zentral.contrib.mdm.software_updates import (
    available_software_updates,
    iter_available_software_updates,
    sync_software_updates,
)
from .utils import force_ota_enrollment_session


class MDMSoftwareUpdateTestCase(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.fake_response = json.load(
            open(os.path.join(os.path.dirname(__file__),
                              "testdata/software_lookup_service_response.json"),
                 "rb")
        )

    # utils

    def _force_enrolled_device(
        self,
        device_id=None,
        os_version=None,
        os_version_extra=None,
        build_version=None,
        build_version_extra=None
    ):
        session, _, _ = force_ota_enrollment_session(self.mbu, completed=True)
        enrolled_device = session.enrolled_device
        if device_id is not None:
            enrolled_device.device_information = {"SoftwareUpdateDeviceID": device_id}
        if os_version:
            enrolled_device.os_version = os_version
        if os_version_extra:
            enrolled_device.os_version_extra = os_version_extra
        if build_version:
            enrolled_device.build_version = build_version
        if build_version_extra:
            enrolled_device.build_version_extra = build_version_extra
        return enrolled_device

    def _force_software_update(
        self,
        device_id,
        version,
        posting_date,
        expiration_date=None,
        public=False,
        version_extra="",
        prerequisite_build="",
    ):
        major, minor, patch = (int(i) for i in version.split("."))
        su = SoftwareUpdate.objects.create(
            public=public,
            major=major,
            minor=minor,
            patch=patch,
            availability=(posting_date, expiration_date),
            extra=version_extra,
            prerequisite_build=prerequisite_build,
        )
        SoftwareUpdateDeviceID.objects.create(software_update=su, device_id=device_id)
        return su

    # software_update __str__

    def test_software_update_str(self):
        su = self._force_software_update(
            device_id="J413AP",
            version="12.6.2",
            posting_date=datetime.date(2022, 12, 13)
        )
        self.assertEqual(str(su), "12.6.2")

    def test_software_update_rsr_str(self):
        su = self._force_software_update(
            device_id="J413AP",
            version="13.3.1",
            posting_date=datetime.date(2023, 5, 2),
            version_extra="(a)",
            prerequisite_build="22E261"
        )
        self.assertEqual(str(su), "13.3.1 (a)")

    # sync_software_update

    @patch("zentral.contrib.mdm.software_updates.requests.get")
    def test_sync_software_update(self, get):
        response_json = Mock()
        response_json.return_value = self.fake_response
        response = Mock()
        response.json = response_json
        get.return_value = response
        sync_software_updates()
        self.assertEqual(SoftwareUpdate.objects.count(), 12)
        self.assertEqual(SoftwareUpdateDeviceID.objects.count(), 18)
        self.assertEqual(SoftwareUpdate.objects.filter(public=True).count(), 4)
        self.assertEqual(SoftwareUpdate.objects.filter(public=False).count(), 8)
        psu = SoftwareUpdate.objects.filter(public=False).order_by("pk").first()
        self.assertEqual(psu.platform, "macOS")
        self.assertEqual(psu.major, 12)
        self.assertEqual(psu.minor, 6)
        self.assertEqual(psu.patch, 2)
        self.assertEqual(
            list(psudi.device_id for psudi in psu.softwareupdatedeviceid_set.all()),
            ["J413AP"],
        )
        self.assertEqual(
            psu.availability,
            DateRange(datetime.date(2022, 12, 13), datetime.date(2023, 4, 20), "[)")
        )
        rsr_su_qs = SoftwareUpdate.objects.filter(extra__gt='')
        self.assertEqual(rsr_su_qs.count(), 1)
        rsr_su = rsr_su_qs.first()
        self.assertEqual(rsr_su.extra, "(a)")
        self.assertEqual(rsr_su.prerequisite_build, "22E261")

    @patch("zentral.contrib.mdm.software_updates.requests.get")
    def test_sync_software_update_update(self, get):
        response_json = Mock()
        response_json.return_value = self.fake_response
        response = Mock()
        response.json = response_json
        get.return_value = response
        sync_software_updates()
        fake_response2 = copy.deepcopy(self.fake_response)
        # add one / remove one device id
        supported_device = fake_response2["PublicAssetSets"]["iOS"][0][
            "SupportedDevices"
        ]
        self.assertEqual(supported_device.pop(), "iPad13,19")
        supported_device.append("iPad13,17")
        self.assertEqual(
            set(
                sudi.device_id
                for sudi in SoftwareUpdateDeviceID.objects.filter(
                    software_update__platform="iOS",
                    software_update__public=True,
                    software_update__major=16,
                    software_update__minor=2,
                    software_update__patch=0,
                )
            ),
            {"iPad13,18", "iPad13,19"},
        )
        # replace one software update
        fake_response2["AssetSets"]["macOS"][0]["ProductVersion"] = "12.6.1"
        self.assertEqual(
            SoftwareUpdate.objects.filter(public=False, major=12, minor=6, patch=2).count(), 1
        )
        self.assertEqual(
            SoftwareUpdate.objects.filter(public=False, major=12, minor=6, patch=1).count(), 0
        )
        # re-run sync with updated response
        response_json.return_value = fake_response2
        sync_software_updates()
        # check updated device ids
        self.assertEqual(
            set(
                sudi.device_id
                for sudi in SoftwareUpdateDeviceID.objects.filter(
                    software_update__platform="iOS",
                    software_update__public=True,
                    software_update__major=16,
                    software_update__minor=2,
                    software_update__patch=0,
                )
            ),
            {"iPad13,17", "iPad13,18"},
        )
        # check replaced software update
        self.assertEqual(
            SoftwareUpdate.objects.filter(public=False, major=12, minor=6, patch=2).count(), 0
        )
        self.assertEqual(
            SoftwareUpdate.objects.filter(public=False, major=12, minor=6, patch=1).count(), 1
        )

    # available_software_updates

    def test_available_software_updates_no_updates_today_no_updates(self):
        enrolled_device = self._force_enrolled_device(device_id="J413AP", os_version="13.1")
        major_update, minor_update, patch_update, rsr_update = available_software_updates(enrolled_device)
        self.assertIsNone(major_update)
        self.assertIsNone(minor_update)
        self.assertIsNone(patch_update)

    def test_available_software_updates_no_updates_no_updates(self):
        enrolled_device = self._force_enrolled_device(device_id="J413AP", os_version="13.1")
        major_update, minor_update, patch_update, rsr_update = available_software_updates(
            enrolled_device,
            date=datetime.date(2023, 1, 21)
        )
        self.assertIsNone(major_update)
        self.assertIsNone(minor_update)
        self.assertIsNone(patch_update)
        self.assertIsNone(rsr_update)

    def test_available_software_updates_one_patch_update(self):
        enrolled_device = self._force_enrolled_device(device_id="J413AP", os_version="12.6.1")
        self._force_software_update(
            device_id="J413AP",
            version="12.6.0",
            posting_date=datetime.date(2022, 12, 1)
        )
        su = self._force_software_update(
            device_id="J413AP",
            version="12.6.2",
            posting_date=datetime.date(2022, 12, 13)
        )
        major_update, minor_update, patch_update, rsr_update = available_software_updates(
            enrolled_device,
            date=datetime.date(2023, 1, 21)
        )
        self.assertIsNone(major_update)
        self.assertIsNone(minor_update)
        self.assertEqual(patch_update, su)
        self.assertEqual(
            list(iter_available_software_updates(enrolled_device, datetime.date(2023, 1, 11))),
            [su]
        )
        self.assertIsNone(rsr_update)

    def test_available_software_updates_one_rsr_update_bad_prerequisite_build(self):
        enrolled_device = self._force_enrolled_device(device_id="J413AP", os_version="13.3.1", build_version="YOLO")
        self._force_software_update(
            device_id="J413AP",
            version="13.3.1",
            posting_date=datetime.date(2023, 5, 2),
            version_extra="(a)",
            public=True,
            prerequisite_build="22E261",
        )
        major_update, minor_update, patch_update, rsr_update = available_software_updates(
            enrolled_device,
            date=datetime.date(2023, 5, 2)
        )
        self.assertIsNone(major_update)
        self.assertIsNone(minor_update)
        self.assertIsNone(patch_update)
        self.assertIsNone(rsr_update)

    def test_available_software_updates_one_rsr_update(self):
        enrolled_device = self._force_enrolled_device(device_id="J413AP", os_version="13.3.1", build_version="22E261")
        su = self._force_software_update(
            device_id="J413AP",
            version="13.3.1",
            posting_date=datetime.date(2023, 5, 2),
            version_extra="(a)",
            prerequisite_build="22E261"
        )
        major_update, minor_update, patch_update, rsr_update = available_software_updates(
            enrolled_device,
            date=datetime.date(2023, 5, 2)
        )
        self.assertIsNone(major_update)
        self.assertIsNone(minor_update)
        self.assertIsNone(patch_update)
        self.assertEqual(rsr_update, su)
        self.assertEqual(
            list(iter_available_software_updates(enrolled_device, datetime.date(2023, 5, 2))),
            [su]
        )

    def test_available_software_updates_one_rsr_update_up_to_date(self):
        enrolled_device = self._force_enrolled_device(
            device_id="J413AP",
            os_version="13.3.1",
            os_version_extra="(a)",
            build_version="22E261",
            build_version_extra="22E772610a"
        )
        self.assertEqual(enrolled_device.current_build_version, "22E772610a")
        self._force_software_update(
            device_id="J413AP",
            version="13.3.1",
            posting_date=datetime.date(2023, 5, 2),
            version_extra="(a)",
            prerequisite_build="22E261"
        )
        major_update, minor_update, patch_update, rsr_update = available_software_updates(
            enrolled_device,
            date=datetime.date(2023, 5, 2)
        )
        self.assertIsNone(major_update)
        self.assertIsNone(minor_update)
        self.assertIsNone(patch_update)
        self.assertIsNone(rsr_update)

    def test_available_software_updates_empty_device_id_no_update(self):
        enrolled_device = self._force_enrolled_device(device_id="", os_version="12.6.1")
        self._force_software_update(
            device_id="J413AP",
            version="12.6.2",
            posting_date=datetime.date(2022, 12, 13)
        )
        major_update, minor_update, patch_update, rsr_update = available_software_updates(
            enrolled_device,
            date=datetime.date(2023, 1, 21)
        )
        self.assertIsNone(major_update)
        self.assertIsNone(minor_update)
        self.assertIsNone(patch_update)
        self.assertIsNone(rsr_update)

    def test_available_software_updates_device_id_not_str_no_update(self):
        enrolled_device = self._force_enrolled_device(device_id=123, os_version="12.6.1")
        self._force_software_update(
            device_id="J413AP",
            version="12.6.2",
            posting_date=datetime.date(2022, 12, 13)
        )
        major_update, minor_update, patch_update, rsr_update = available_software_updates(
            enrolled_device,
            date=datetime.date(2023, 1, 21)
        )
        self.assertIsNone(major_update)
        self.assertIsNone(minor_update)
        self.assertIsNone(patch_update)
        self.assertIsNone(rsr_update)

    def test_available_software_updates_device_id_not_found_no_update(self):
        enrolled_device = self._force_enrolled_device(device_id="J413AP", os_version="12.6")
        su = self._force_software_update(
            device_id="J413AP",
            version="12.6.2",
            posting_date=datetime.date(2022, 12, 13)
        )
        major_update, minor_update, patch_update, rsr_update = available_software_updates(
            enrolled_device,
            date=datetime.date(2023, 1, 21)
        )
        self.assertIsNone(major_update)
        self.assertIsNone(minor_update)
        self.assertEqual(patch_update, su)
        self.assertIsNone(rsr_update)

    def test_available_software_updates_no_os_version_no_update(self):
        enrolled_device = self._force_enrolled_device(device_id="J413AP")
        self._force_software_update(
            device_id="J413AP",
            version="12.6.2",
            posting_date=datetime.date(2022, 12, 13)
        )
        major_update, minor_update, patch_update, rsr_update = available_software_updates(
            enrolled_device,
            date=datetime.date(2023, 1, 21)
        )
        self.assertIsNone(major_update)
        self.assertIsNone(minor_update)
        self.assertIsNone(patch_update)

    def test_available_software_updates_one_expired_patch_update(self):
        enrolled_device = self._force_enrolled_device(device_id="J413AP", os_version="12.6.1")
        self._force_software_update(
            device_id="J413AP",
            version="12.6.2",
            posting_date=datetime.date(2022, 12, 13),
            expiration_date=datetime.date(2023, 4, 28),
        )
        major_update, minor_update, patch_update, rsr_update = available_software_updates(
            enrolled_device,
            date=datetime.date(2023, 5, 21)
        )
        self.assertIsNone(major_update)
        self.assertIsNone(minor_update)
        self.assertIsNone(patch_update)
        self.assertEqual(len(list(iter_available_software_updates(enrolled_device, datetime.date(2023, 5, 21)))), 0)

    def test_available_software_updates_all_updates(self):
        enrolled_device = self._force_enrolled_device(device_id="J413AP", os_version="12.6.1")
        self._force_software_update(
            device_id="J413AP",
            version="12.6.2",
            posting_date=datetime.date(2022, 12, 13),
            expiration_date=datetime.date(2023, 4, 28),
        )
        su_p = self._force_software_update(
            device_id="J413AP",
            version="12.6.3",
            posting_date=datetime.date(2022, 12, 13),
            expiration_date=datetime.date(2023, 5, 28),
        )
        su_mi = self._force_software_update(
            device_id="J413AP",
            version="12.7.0",
            posting_date=datetime.date(2022, 12, 31),
            expiration_date=datetime.date(2023, 6, 28),
        )
        self._force_software_update(
            device_id="J413AP",
            version="13.0.0",
            posting_date=datetime.date(2022, 12, 31),
            expiration_date=datetime.date(2023, 6, 28),
        )
        su_ma = self._force_software_update(
            device_id="J413AP",
            version="13.1.0",
            posting_date=datetime.date(2022, 12, 31),
            expiration_date=datetime.date(2023, 6, 28),
        )
        major_update, minor_update, patch_update, rsr_update = available_software_updates(
            enrolled_device,
            date=datetime.date(2023, 1, 11)
        )
        self.assertEqual(major_update, su_ma)
        self.assertEqual(minor_update, su_mi)
        self.assertEqual(patch_update, su_p)
        self.assertEqual(
            list(iter_available_software_updates(enrolled_device, datetime.date(2023, 1, 11))),
            [su_ma, su_mi, su_p]
        )

    # management command

    @patch("zentral.contrib.mdm.software_updates.requests.get")
    def test_management_command(self, get):
        response_json = Mock()
        response_json.return_value = self.fake_response
        response = Mock()
        response.json = response_json
        get.return_value = response
        call_command("sync_software_updates")
        response_json.assert_called_once_with()
        self.assertEqual(SoftwareUpdate.objects.count(), 12)
        self.assertEqual(SoftwareUpdateDeviceID.objects.count(), 18)
        self.assertEqual(SoftwareUpdate.objects.filter(public=True).count(), 4)
        self.assertEqual(SoftwareUpdate.objects.filter(public=False).count(), 8)

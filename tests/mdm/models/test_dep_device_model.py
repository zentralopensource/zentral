from datetime import datetime, timezone
from django.test import TestCase
from tests.mdm.utils import force_dep_device
from tests.zentral_test_utils.assertions.serialization_assertions import SerializeForEventAssertions


class TestMDMDEPDeviceModel(TestCase, SerializeForEventAssertions):
    maxDiff = None

    def test_dep_device_serialize_for_event_keys_only(self):
        dep_device = force_dep_device()
        self.assertEqual(
            dep_device.serialize_for_event(keys_only=True),
            {"pk": dep_device.pk, "serial_number": dep_device.serial_number},
        )

    def test_dep_device_serialize_for_event(self):
        dep_device = force_dep_device()
        d = dep_device.serialize_for_event()
        self.assertEqual(d["serial_number"], dep_device.serial_number)
        self.assertEqual(d["virtual_server"]["pk"], dep_device.virtual_server.pk)
        # every attribute a profile assignment or a refresh can change has to be reported
        self.assertEqual(
            set(d),
            {"pk", "serial_number", "virtual_server", "enrollment",
             "asset_tag", "color", "description", "device_family", "model", "os",
             "eid", "imei", "meid",
             "bluetooth_mac_address", "ethernet_mac_address", "wifi_mac_address",
             "is_replacement_device", "released_by_replacement",
             "device_assigned_by", "device_assigned_date", "mdm_migration_deadline",
             "last_op_type", "last_op_date",
             "profile_status", "profile_uuid", "profile_assign_time", "profile_push_time",
             "disowned_at", "created_at", "updated_at"},
        )
        self.assert_serialize_for_event_is_json_native(dep_device)

    def test_dep_device_serialize_for_event_makes_the_datetimes_naive(self):
        # dep_device_update_dict() assigns the datetimes it parses from the DEP API straight onto
        # the model, so they are aware, while the same field read back from the database is naive
        # because USE_TZ is off. The payload must not depend on which one it was built from.
        dep_device = force_dep_device()
        for profile_assign_time in (datetime(2023, 6, 17, 15, 41, 6, tzinfo=timezone.utc),
                                    datetime(2023, 6, 17, 15, 41, 6)):
            with self.subTest(tzinfo=profile_assign_time.tzinfo):
                dep_device.profile_assign_time = profile_assign_time
                self.assertEqual(dep_device.serialize_for_event()["profile_assign_time"],
                                 "2023-06-17T15:41:06")

    def test_dep_device_serialize_for_event_without_enrollment(self):
        dep_device = force_dep_device()
        self.assertIsNone(dep_device.enrollment)
        self.assertIsNone(dep_device.serialize_for_event()["enrollment"])
        self.assert_serialize_for_event_is_json_native(dep_device)

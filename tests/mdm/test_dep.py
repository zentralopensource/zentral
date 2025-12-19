from datetime import datetime
from unittest.mock import Mock, patch
import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.dep import define_dep_profile, sync_dep_virtual_server_devices
from zentral.contrib.mdm.dep_client import CursorIterator
from zentral.contrib.mdm.models import DEPDevice
from zentral.contrib.mdm.tasks import define_dep_profile_task
from .utils import force_dep_device, force_dep_enrollment, force_dep_virtual_server


class TestDEPEnrollment(TestCase):
    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_token")
    def test_sync_dep_virtual_server_devices_fetch(self, from_dep_token):
        client = Mock()
        enrollment = force_dep_enrollment(MetaBusinessUnit.objects.create(name=get_random_string(12)))
        server = enrollment.virtual_server
        serial_number = get_random_string(10).upper()
        client.fetch_devices.return_value = CursorIterator([
            {'color': 'SPACE GRAY',
             'description': 'IPHONE X SPACE GRAY 64GB-ZDD',
             'device_assigned_by': 'support@zentral.com',
             'device_assigned_date': '2023-01-10T19:09:22Z',
             'device_family': 'iPhone',
             'model': 'iPhone X',
             'op_date': '2023-06-17T15:41:06Z',
             'op_type': 'modified',
             'os': 'iOS',
             'profile_assign_time': '2023-01-10T19:07:41Z',
             'profile_push_time': '2023-06-17T15:41:06Z',
             'profile_status': 'pushed',
             'profile_uuid': str(enrollment.uuid).upper().replace("-", ""),
             'serial_number': serial_number}
        ])
        from_dep_token.return_value = client
        server = force_dep_virtual_server()
        self.assertIsNone(server.token.sync_cursor)  # → fetch
        dep_devices = list(sync_dep_virtual_server_devices(server))
        client.fetch_devices.assert_called_once_with()
        self.assertEqual(len(dep_devices), 1)
        d, d_created = dep_devices[0]
        d.refresh_from_db()  # for the datetimes, to get the stored ones, not the parsed ones
        self.assertTrue(d_created)
        self.assertEqual(d.asset_tag, "")
        self.assertEqual(d.color, "SPACE GRAY")
        self.assertEqual(d.description, "IPHONE X SPACE GRAY 64GB-ZDD")
        self.assertEqual(d.device_family, "iPhone")
        self.assertEqual(d.device_assigned_by, "support@zentral.com")
        self.assertEqual(d.device_assigned_date, datetime(2023, 1, 10, 19, 9, 22))
        self.assertEqual(d.model, "iPhone X")
        self.assertIsNone(d.last_op_date)
        self.assertIsNone(d.last_op_type)
        self.assertEqual(d.os, "iOS")
        self.assertEqual(d.profile_assign_time, datetime(2023, 1, 10, 19, 7, 41))
        self.assertEqual(d.profile_push_time, datetime(2023, 6, 17, 15, 41, 6))
        self.assertEqual(d.profile_uuid, enrollment.uuid)
        self.assertEqual(d.serial_number, serial_number)
        self.assertEqual(d.enrollment, enrollment)

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_token")
    def test_sync_dep_virtual_server_devices_sync(self, from_dep_token):
        client = Mock()
        profile_uuid = uuid.uuid4()
        serial_number = get_random_string(10).upper()
        sync_cursor = get_random_string(12)
        new_sync_cursor = get_random_string(12)

        def device_iterator():
            yield from [
                {'color': 'SPACE GRAY',
                 'description': 'IPHONE X SPACE GRAY 64GB-ZDD',
                 'device_assigned_by': 'support@zentral.com',
                 'device_assigned_date': '2023-01-10T19:09:22Z',
                 'device_family': 'iPhone',
                 'model': 'iPhone X',
                 'op_date': '2023-06-17T15:41:06Z',
                 'op_type': 'modified',
                 'os': 'iOS',
                 'profile_assign_time': '2023-01-10T19:07:41Z',
                 'profile_push_time': '2023-06-17T15:41:06Z',
                 'profile_status': 'pushed',
                 'profile_uuid': str(profile_uuid).upper().replace("-", ""),
                 'serial_number': serial_number}
            ]
            return new_sync_cursor

        client.sync_devices.return_value = CursorIterator(device_iterator())
        from_dep_token.return_value = client
        server = force_dep_virtual_server()
        server.token.sync_cursor = sync_cursor  # → sync
        server.token.save()
        self.assertIsNone(server.token.last_synced_at)
        start = datetime.utcnow()
        dep_devices = list(sync_dep_virtual_server_devices(server))
        client.sync_devices.assert_called_once_with(sync_cursor)
        self.assertEqual(len(dep_devices), 1)
        d, d_created = dep_devices[0]
        d.refresh_from_db()  # for the datetimes, to get the stored ones, not the parsed ones
        self.assertTrue(d_created)
        self.assertEqual(d.asset_tag, "")
        self.assertEqual(d.color, "SPACE GRAY")
        self.assertEqual(d.description, "IPHONE X SPACE GRAY 64GB-ZDD")
        self.assertEqual(d.device_family, "iPhone")
        self.assertEqual(d.device_assigned_by, "support@zentral.com")
        self.assertEqual(d.device_assigned_date, datetime(2023, 1, 10, 19, 9, 22))
        self.assertEqual(d.model, "iPhone X")
        self.assertEqual(d.last_op_date, datetime(2023, 6, 17, 15, 41, 6))
        self.assertEqual(d.last_op_type, "modified")
        self.assertEqual(d.os, "iOS")
        self.assertEqual(d.profile_assign_time, datetime(2023, 1, 10, 19, 7, 41))
        self.assertEqual(d.profile_push_time, datetime(2023, 6, 17, 15, 41, 6))
        self.assertEqual(d.profile_uuid, profile_uuid)
        self.assertEqual(d.serial_number, serial_number)
        self.assertIsNone(d.enrollment)  # unknown profile (random UUID)
        self.assertEqual(server.token.sync_cursor, new_sync_cursor)
        self.assertTrue(server.token.last_synced_at > start)

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_token")
    def test_sync_dep_virtual_server_devices_assign_default_profile(self, from_dep_token):
        serial_number = get_random_string(10).upper()

        enrollment = force_dep_enrollment(MetaBusinessUnit.objects.create(name=get_random_string(12)))
        server = enrollment.virtual_server
        server.default_enrollment = enrollment
        server.save()

        def device_iterator():
            yield from [
                {'color': 'SPACE GRAY',
                 'description': 'IPHONE X SPACE GRAY 64GB-ZDD',
                 'device_assigned_by': 'support@zentral.com',
                 'device_assigned_date': '2023-01-10T19:09:22Z',
                 'device_family': 'iPhone',
                 'model': 'iPhone X',
                 'op_date': '2023-01-10T19:07:41Z',
                 'op_type': 'modified',
                 'os': 'iOS',
                 'profile_status': 'empty',
                 'serial_number': serial_number}
            ]
            return get_random_string(12)

        client = Mock()
        client.fetch_devices.return_value = CursorIterator(device_iterator())
        client.assign_profile.return_value = {"devices": {serial_number: "SUCCESS"}}
        from_dep_token.return_value = client
        dep_devices = list(sync_dep_virtual_server_devices(server))
        client.fetch_devices.assert_called_once_with()
        client.assign_profile.assert_called_once_with(server.default_enrollment.uuid, [serial_number])
        self.assertEqual(len(dep_devices), 1)
        device, created = dep_devices[0]
        self.assertIsNone(device.profile_uuid)
        self.assertIsNone(device.enrollment)
        device.refresh_from_db()
        self.assertEqual(device.profile_uuid, server.default_enrollment.uuid)
        self.assertEqual(device.enrollment, server.default_enrollment)
        self.assertEqual(device.profile_status, "assigned")

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_token")
    def test_sync_dep_virtual_server_deleted_device_no_assign_default_profile(self, from_dep_token):
        serial_number = get_random_string(10).upper()

        enrollment = force_dep_enrollment(MetaBusinessUnit.objects.create(name=get_random_string(12)))
        server = enrollment.virtual_server
        server.default_enrollment = enrollment
        server.save()

        def device_iterator():
            yield from [
                {'color': 'SPACE GRAY',
                 'description': 'IPHONE X SPACE GRAY 64GB-ZDD',
                 'device_assigned_by': 'support@zentral.com',
                 'device_assigned_date': '2023-01-10T19:09:22Z',
                 'device_family': 'iPhone',
                 'model': 'iPhone X',
                 'op_date': '2023-01-10T19:07:41Z',
                 'op_type': 'deleted',
                 'os': 'iOS',
                 'serial_number': serial_number}
            ]
            return get_random_string(12)

        client = Mock()
        client.fetch_devices.return_value = CursorIterator(device_iterator())
        from_dep_token.return_value = client
        dep_devices = list(sync_dep_virtual_server_devices(server))
        client.fetch_devices.assert_called_once_with()
        client.assign_profile.assert_not_called()
        self.assertEqual(len(dep_devices), 1)
        device, created = dep_devices[0]
        self.assertIsNone(device.profile_uuid)
        self.assertIsNone(device.enrollment)
        device.refresh_from_db()
        self.assertIsNone(device.profile_uuid)
        self.assertIsNone(device.enrollment)
        self.assertEqual(device.profile_status, "empty")

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_token")
    def test_define_dep_profile(self, from_dep_token):
        enrollment = force_dep_enrollment(MetaBusinessUnit.objects.create(name=get_random_string(12)))
        prev_profile_uuid = enrollment.uuid
        device1 = force_dep_device(
            server=enrollment.virtual_server,
            profile_status=DEPDevice.PROFILE_STATUS_EMPTY,
        )
        device2 = force_dep_device(
            server=enrollment.virtual_server,
            profile_status=DEPDevice.PROFILE_STATUS_ASSIGNED,
            enrollment=enrollment
        )
        device3 = force_dep_device(
            server=enrollment.virtual_server,
            profile_status=DEPDevice.PROFILE_STATUS_ASSIGNED,
            enrollment=enrollment
        )
        enrollment2 = force_dep_enrollment(MetaBusinessUnit.objects.create(name=get_random_string(12)))
        device4 = force_dep_device(
            server=enrollment2.virtual_server,
            profile_status=DEPDevice.PROFILE_STATUS_ASSIGNED,
            enrollment=enrollment2
        )
        client = Mock()
        profile_uuid = uuid.uuid4()
        self.assertNotEqual(enrollment.uuid, profile_uuid)
        self.assertNotEqual(device1.profile_uuid, profile_uuid)
        self.assertFalse(device2.is_deleted())
        client.add_profile.return_value = {
            "profile_uuid": str(profile_uuid).upper().replace("-", ""),
            "devices": {
                device1.serial_number: "SUCCESS",
                device2.serial_number: "NOT_ACCESSIBLE",
                device3.serial_number: "FAILED",
                device4.serial_number: "NOT_ACCESSIBLE",
                "yolo": "fomo",
            }
        }
        from_dep_token.return_value = client
        result = define_dep_profile(enrollment)
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.uuid, profile_uuid)
        self.assertEqual(
            result,
            {'devices': {'failed': [device3.serial_number],
                         'not_accessible': [device2.serial_number,
                                            device4.serial_number],
                         'success': [device1.serial_number]},
             'display_name': enrollment.display_name,
             'name': enrollment.name,
             'pk': enrollment.pk,
             'uuid': str(profile_uuid)}
        )
        # device1 updated
        device1.refresh_from_db()
        self.assertEqual(device1.profile_status, DEPDevice.PROFILE_STATUS_ASSIGNED)
        self.assertEqual(device1.profile_uuid, profile_uuid)
        # device2 deleted because NOT_ACCESSIBLE
        device2.refresh_from_db()
        self.assertTrue(device2.is_deleted())
        # device3 not changed because FAILED
        device3.refresh_from_db()
        self.assertEqual(device3.profile_status, DEPDevice.PROFILE_STATUS_ASSIGNED)
        self.assertEqual(device3.profile_uuid, prev_profile_uuid)
        # device4 not deleted because not part of the same virtual server
        device4.refresh_from_db()
        self.assertFalse(device4.is_deleted())
        self.assertEqual(device4.profile_status, DEPDevice.PROFILE_STATUS_ASSIGNED)
        self.assertEqual(device4.profile_uuid, enrollment2.uuid)

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_token")
    def test_define_dep_profile_task(self, from_dep_token):
        enrollment = force_dep_enrollment(MetaBusinessUnit.objects.create(name=get_random_string(12)))
        client = Mock()
        profile_uuid = uuid.uuid4()
        self.assertNotEqual(enrollment.uuid, profile_uuid)
        client.add_profile.return_value = {
            "profile_uuid": str(profile_uuid).upper().replace("-", ""),
            "devices": {},
        }
        from_dep_token.return_value = client
        result = define_dep_profile_task(enrollment.pk)
        self.assertEqual(
            result,
            {'devices': {'failed': [], 'not_accessible': [], 'success': []},
             'display_name': enrollment.display_name,
             'name': enrollment.name,
             'pk': enrollment.pk,
             'uuid': str(profile_uuid)}
        )

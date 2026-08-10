import uuid
from datetime import datetime
from unittest.mock import Mock, patch

from django.test import TestCase
from django.utils.crypto import get_random_string

from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.dep import (
    assign_dep_virtual_server_default_enrollment,
    define_dep_profile,
    iter_unassigned_dep_device_serial_numbers,
    sync_dep_virtual_server_devices,
)
from zentral.contrib.mdm.dep_client import DEVICE_BATCH_SIZE, CursorIterator
from zentral.contrib.mdm.models import DEPDevice
from zentral.contrib.mdm.tasks import define_dep_profile_task
from zentral.utils.time import naive_utcnow

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
        d, d_action = dep_devices[0]
        d.refresh_from_db()  # for the datetimes, to get the stored ones, not the parsed ones
        self.assertEqual(d_action, "created")
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
        start = naive_utcnow()
        dep_devices = list(sync_dep_virtual_server_devices(server))
        client.sync_devices.assert_called_once_with(sync_cursor)
        self.assertEqual(len(dep_devices), 1)
        d, d_action = dep_devices[0]
        d.refresh_from_db()  # for the datetimes, to get the stored ones, not the parsed ones
        self.assertEqual(d_action, "created")
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
    def test_sync_dep_virtual_server_devices_does_not_assign_the_default_profile(self, from_dep_token):
        serial_number = get_random_string(10).upper()

        enrollment = force_dep_enrollment(MetaBusinessUnit.objects.create(name=get_random_string(12)))
        server = enrollment.virtual_server
        server.default_enrollment = enrollment
        server.save()

        def device_iterator():
            yield from [
                {'device_assigned_by': 'support@zentral.com',
                 'device_assigned_date': '2023-01-10T19:09:22Z',
                 'op_date': '2023-01-10T19:07:41Z',
                 'op_type': 'modified',
                 'profile_status': 'empty',
                 'serial_number': serial_number}
            ]
            return get_random_string(12)

        client = Mock()
        client.fetch_devices.return_value = CursorIterator(device_iterator())
        from_dep_token.return_value = client
        dep_devices = list(sync_dep_virtual_server_devices(server))
        client.fetch_devices.assert_called_once_with()
        # the assignment is a separate task now, the synchronization does not talk to Apple about it
        client.assign_profile.assert_not_called()
        self.assertEqual(len(dep_devices), 1)
        device, _ = dep_devices[0]
        device.refresh_from_db()
        self.assertIsNone(device.profile_uuid)
        self.assertIsNone(device.enrollment)

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_token")
    def test_sync_dep_virtual_server_devices_fetch_marks_missing_deleted(self, from_dep_token):
        server = force_dep_virtual_server()
        dep_device = force_dep_device(server=server, profile_status=DEPDevice.PROFILE_STATUS_EMPTY)
        prev_updated_at = dep_device.updated_at
        client = Mock()
        client.fetch_devices.return_value = CursorIterator([
            {'device_assigned_by': 'support@zentral.com',
             'device_assigned_date': '2023-01-10T19:09:22Z',
             'serial_number': get_random_string(10).upper()}
        ])
        from_dep_token.return_value = client
        results = list(sync_dep_virtual_server_devices(server, force_fetch=True))
        self.assertEqual([action for _, action in results], ["created", "marked_deleted"])
        dep_device.refresh_from_db()
        self.assertEqual(dep_device.last_op_type, DEPDevice.OP_TYPE_DELETED)
        self.assertTrue(dep_device.updated_at > prev_updated_at)

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_token")
    def test_sync_dep_virtual_server_devices_fetch_leaves_the_deleted_ones_alone(self, from_dep_token):
        server = force_dep_virtual_server()
        dep_device = force_dep_device(server=server, profile_status=DEPDevice.PROFILE_STATUS_EMPTY,
                                      op_type=DEPDevice.OP_TYPE_DELETED)
        prev_updated_at = dep_device.updated_at
        client = Mock()
        client.fetch_devices.return_value = CursorIterator([])
        from_dep_token.return_value = client
        self.assertEqual(list(sync_dep_virtual_server_devices(server, force_fetch=True)), [])
        dep_device.refresh_from_db()
        # a device already marked as deleted is not rewritten on every full fetch
        self.assertEqual(dep_device.updated_at, prev_updated_at)

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_token")
    def test_sync_dep_virtual_server_devices_unchanged_device_is_not_written(self, from_dep_token):
        server = force_dep_virtual_server()
        device_d = {'color': 'SPACE GRAY',
                    'description': 'IPHONE X SPACE GRAY 64GB-ZDD',
                    'device_assigned_by': 'support@zentral.com',
                    'device_assigned_date': '2023-01-10T19:09:22Z',
                    'device_family': 'iPhone',
                    'model': 'iPhone X',
                    'os': 'iOS',
                    'profile_status': 'empty',
                    'serial_number': get_random_string(10).upper()}
        client = Mock()
        client.fetch_devices.return_value = CursorIterator([device_d])
        from_dep_token.return_value = client
        results = list(sync_dep_virtual_server_devices(server, force_fetch=True))
        self.assertEqual([action for _, action in results], ["created"])
        dep_device = results[0][0]
        prev_updated_at = dep_device.updated_at

        # the very same device, reported again
        client.fetch_devices.return_value = CursorIterator([device_d])
        results = list(sync_dep_virtual_server_devices(server, force_fetch=True))
        self.assertEqual([action for _, action in results], ["unchanged"])
        dep_device.refresh_from_db()
        self.assertEqual(dep_device.updated_at, prev_updated_at)

        # one attribute moves
        client.fetch_devices.return_value = CursorIterator([dict(device_d, color="MIDNIGHT")])
        results = list(sync_dep_virtual_server_devices(server, force_fetch=True))
        self.assertEqual([action for _, action in results], ["updated"])
        dep_device.refresh_from_db()
        self.assertEqual(dep_device.color, "MIDNIGHT")
        self.assertTrue(dep_device.updated_at > prev_updated_at)

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
        self.assertEqual(len(dep_devices), 1)
        device, created = dep_devices[0]
        device.refresh_from_db()
        self.assertEqual(device.last_op_type, DEPDevice.OP_TYPE_DELETED)
        # a deleted device is not a candidate for the default enrollment
        self.assertNotIn(device.serial_number, list(iter_unassigned_dep_device_serial_numbers(server)))

    # default enrollment assignment

    def force_server_with_default_enrollment(self):
        enrollment = force_dep_enrollment(MetaBusinessUnit.objects.create(name=get_random_string(12)))
        server = enrollment.virtual_server
        server.default_enrollment = enrollment
        server.save()
        return server, enrollment

    def test_iter_unassigned_dep_device_serial_numbers(self):
        server, enrollment = self.force_server_with_default_enrollment()
        unassigned = force_dep_device(server=server, profile_status=DEPDevice.PROFILE_STATUS_EMPTY)
        # a full fetch leaves last_op_type null, and those devices must be candidates too:
        # excluding the deleted ones must not exclude the ones with no operation at all
        DEPDevice.objects.filter(pk=unassigned.pk).update(last_op_type=None)
        removed = force_dep_device(server=server, profile_status=DEPDevice.PROFILE_STATUS_ASSIGNED,
                                   enrollment=enrollment)
        DEPDevice.objects.filter(pk=removed.pk).update(profile_status=DEPDevice.PROFILE_STATUS_REMOVED)
        assigned = force_dep_device(server=server, profile_status=DEPDevice.PROFILE_STATUS_ASSIGNED,
                                    enrollment=enrollment)
        deleted = force_dep_device(server=server, profile_status=DEPDevice.PROFILE_STATUS_EMPTY,
                                   op_type=DEPDevice.OP_TYPE_DELETED)
        disowned = force_dep_device(server=server, profile_status=DEPDevice.PROFILE_STATUS_EMPTY)
        DEPDevice.objects.filter(pk=disowned.pk).update(disowned_at=naive_utcnow())
        other_server_device = force_dep_device(profile_status=DEPDevice.PROFILE_STATUS_EMPTY)

        serial_numbers = sorted(iter_unassigned_dep_device_serial_numbers(server))
        self.assertEqual(serial_numbers, sorted([unassigned.serial_number, removed.serial_number]))
        for device in (assigned, deleted, disowned, other_server_device):
            self.assertNotIn(device.serial_number, serial_numbers)

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_virtual_server")
    def test_assign_dep_virtual_server_default_enrollment(self, from_dep_virtual_server):
        server, enrollment = self.force_server_with_default_enrollment()
        device = force_dep_device(server=server, profile_status=DEPDevice.PROFILE_STATUS_EMPTY)
        prev_updated_at = device.updated_at
        client = Mock()
        client.get_device_batch_size.return_value = DEVICE_BATCH_SIZE
        client.assign_profile.return_value = {"devices": {device.serial_number: "SUCCESS"}}
        client.get_devices.return_value = {
            device.serial_number: {
                "profile_uuid": str(enrollment.uuid).upper().replace("-", ""),
                # Apple has already pushed it, which the assignment could not have guessed
                "profile_status": "pushed",
                "profile_assign_time": "2026-08-10T09:15:22Z",
                "profile_push_time": "2026-08-10T09:16:01Z",
            }
        }
        from_dep_virtual_server.return_value = client

        self.assertEqual(assign_dep_virtual_server_default_enrollment(server),
                         {"assigned": 1, "failed": 0})
        client.assign_profile.assert_called_once_with(enrollment.uuid, [device.serial_number])
        client.get_devices.assert_called_once_with([device.serial_number])
        device.refresh_from_db()
        self.assertEqual(device.enrollment, enrollment)
        self.assertEqual(device.profile_uuid, enrollment.uuid)
        # what Apple reports, not what the assignment assumed
        self.assertEqual(device.profile_status, DEPDevice.PROFILE_STATUS_PUSHED)
        self.assertEqual(device.profile_assign_time, datetime(2026, 8, 10, 9, 15, 22))
        self.assertEqual(device.profile_push_time, datetime(2026, 8, 10, 9, 16, 1))
        # bulk_update bypasses save(), so auto_now would not have fired
        self.assertTrue(device.updated_at > prev_updated_at)
        # the device is not a candidate anymore
        self.assertEqual(list(iter_unassigned_dep_device_serial_numbers(server)), [])

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_virtual_server")
    def test_assign_dep_virtual_server_default_enrollment_not_reported_back(self, from_dep_virtual_server):
        server, enrollment = self.force_server_with_default_enrollment()
        device = force_dep_device(server=server, profile_status=DEPDevice.PROFILE_STATUS_EMPTY)
        client = Mock()
        client.get_device_batch_size.return_value = DEVICE_BATCH_SIZE
        client.assign_profile.return_value = {"devices": {device.serial_number: "SUCCESS"}}
        # Apple accepted the assignment but does not report the device back
        client.get_devices.return_value = {}
        from_dep_virtual_server.return_value = client

        self.assertEqual(assign_dep_virtual_server_default_enrollment(server),
                         {"assigned": 0, "failed": 0})
        device.refresh_from_db()
        self.assertIsNone(device.enrollment)
        # nothing was written, so it stays a candidate for the next run
        self.assertEqual(list(iter_unassigned_dep_device_serial_numbers(server)), [device.serial_number])

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_virtual_server")
    def test_assign_dep_virtual_server_default_enrollment_failure(self, from_dep_virtual_server):
        server, enrollment = self.force_server_with_default_enrollment()
        device = force_dep_device(server=server, profile_status=DEPDevice.PROFILE_STATUS_EMPTY)
        client = Mock()
        client.get_device_batch_size.return_value = DEVICE_BATCH_SIZE
        client.assign_profile.return_value = {"devices": {device.serial_number: "FAILED"}}
        from_dep_virtual_server.return_value = client

        self.assertEqual(assign_dep_virtual_server_default_enrollment(server),
                         {"assigned": 0, "failed": 1})
        device.refresh_from_db()
        self.assertIsNone(device.enrollment)
        # it stays a candidate, the next synchronization enqueues the task again
        self.assertEqual(list(iter_unassigned_dep_device_serial_numbers(server)), [device.serial_number])

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_virtual_server")
    def test_assign_dep_virtual_server_default_enrollment_chunks(self, from_dep_virtual_server):
        server, enrollment = self.force_server_with_default_enrollment()
        devices = [force_dep_device(server=server, profile_status=DEPDevice.PROFILE_STATUS_EMPTY)
                   for _ in range(3)]
        serial_numbers = sorted(d.serial_number for d in devices)
        client = Mock()
        client.get_device_batch_size.return_value = 2
        client.assign_profile.side_effect = [
            {"devices": {sn: "SUCCESS" for sn in serial_numbers[:2]}},
            {"devices": {serial_numbers[2]: "SUCCESS"}},
        ]
        profile_uuid = str(enrollment.uuid).upper().replace("-", "")
        client.get_devices.side_effect = [
            {sn: {"profile_uuid": profile_uuid, "profile_status": "assigned"} for sn in serial_numbers[:2]},
            {serial_numbers[2]: {"profile_uuid": profile_uuid, "profile_status": "assigned"}},
        ]
        from_dep_virtual_server.return_value = client

        self.assertEqual(assign_dep_virtual_server_default_enrollment(server),
                         {"assigned": 3, "failed": 0})
        self.assertEqual(
            [c.args[1] for c in client.assign_profile.call_args_list],
            [serial_numbers[:2], serial_numbers[2:]]
        )

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_virtual_server")
    def test_assign_dep_virtual_server_default_enrollment_no_default(self, from_dep_virtual_server):
        server = force_dep_virtual_server()
        force_dep_device(server=server, profile_status=DEPDevice.PROFILE_STATUS_EMPTY)
        self.assertEqual(assign_dep_virtual_server_default_enrollment(server),
                         {"assigned": 0, "failed": 0})
        from_dep_virtual_server.assert_not_called()

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_virtual_server")
    def test_assign_dep_virtual_server_default_enrollment_nothing_to_do(self, from_dep_virtual_server):
        server, enrollment = self.force_server_with_default_enrollment()
        force_dep_device(server=server, profile_status=DEPDevice.PROFILE_STATUS_ASSIGNED,
                         enrollment=enrollment)
        client = Mock()
        client.get_device_batch_size.return_value = DEVICE_BATCH_SIZE
        from_dep_virtual_server.return_value = client
        self.assertEqual(assign_dep_virtual_server_default_enrollment(server),
                         {"assigned": 0, "failed": 0})
        client.assign_profile.assert_not_called()

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
        client.get_device_batch_size.return_value = DEVICE_BATCH_SIZE
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
    def test_define_dep_profile_over_the_limit_assigns_the_rest(self, from_dep_token):
        enrollment = force_dep_enrollment(MetaBusinessUnit.objects.create(name=get_random_string(12)))
        devices = [
            force_dep_device(server=enrollment.virtual_server,
                             profile_status=DEPDevice.PROFILE_STATUS_ASSIGNED,
                             enrollment=enrollment)
            for _ in range(3)
        ]
        # serialize_dep_profile() lists them in the DEPDevice ordering, by serial number
        serial_numbers = sorted(d.serial_number for d in devices)
        client = Mock()
        # the profile payload is split at the size the client resolves for /profile
        client.get_device_batch_size.return_value = 2
        profile_uuid = uuid.uuid4()
        client.add_profile.return_value = {
            "profile_uuid": str(profile_uuid).upper().replace("-", ""),
            "devices": {sn: "SUCCESS" for sn in serial_numbers[:2]},
        }
        client.assign_profile.return_value = {"devices": {serial_numbers[2]: "SUCCESS"}}
        from_dep_token.return_value = client
        result = define_dep_profile(enrollment)
        # only the first batch rides in the profile payload
        profile_payload = client.add_profile.call_args.args[0]
        self.assertEqual(sorted(profile_payload["devices"]), serial_numbers[:2])
        # the rest is assigned once the profile has a UUID, as Apple returned it
        client.assign_profile.assert_called_once_with(
            str(profile_uuid).upper().replace("-", ""), [serial_numbers[2]]
        )
        # the statuses of both calls end up in the same result
        self.assertEqual(sorted(result["devices"]["success"]), serial_numbers)
        for device in devices:
            device.refresh_from_db()
            self.assertEqual(device.profile_uuid, profile_uuid)
            self.assertEqual(device.profile_status, DEPDevice.PROFILE_STATUS_ASSIGNED)

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_token")
    def test_define_dep_profile_task(self, from_dep_token):
        enrollment = force_dep_enrollment(MetaBusinessUnit.objects.create(name=get_random_string(12)))
        client = Mock()
        client.get_device_batch_size.return_value = DEVICE_BATCH_SIZE
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

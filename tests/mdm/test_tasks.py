import json
import os.path
from unittest.mock import Mock, patch

from celery.exceptions import MaxRetriesExceededError, Retry
from django.test import TestCase
from django.utils.crypto import get_random_string

from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.dep import DEPClientError
from zentral.contrib.mdm.dep_client import CursorIterator
from zentral.contrib.mdm.tasks import (
    assign_dep_virtual_server_default_enrollment_task,
    bulk_assign_location_asset_task,
    sync_dep_virtual_server_devices_task,
    sync_software_updates_task,
)

from .utils import (
    force_dep_enrollment,
    force_dep_virtual_server,
    force_location_asset,
)


class MDMTasksTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        with open(
            os.path.join(
                os.path.dirname(__file__),
                "testdata/software_lookup_service_response.json"
            ), "rb"
        ) as f:
            cls.fake_response = json.load(f)

    @patch("zentral.contrib.mdm.tasks.bulk_assign_location_asset")
    def test_bulk_assign_location_asset_task(self, bulk_assign_location_asset):
        location_asset = force_location_asset()
        dep_virtual_server = force_dep_virtual_server()
        bulk_assign_location_asset.return_value = 42
        self.assertEqual(
            bulk_assign_location_asset_task(location_asset.pk, [dep_virtual_server.pk]),
            {'dep_virtual_servers': [{'name': dep_virtual_server.name,
                                      'pk': dep_virtual_server.pk,
                                      'uuid': str(dep_virtual_server.uuid)}],
             'location_asset': {'asset': {'adam_id': location_asset.asset.adam_id,
                                          'pk': location_asset.asset.pk,
                                          'pricing_param': location_asset.asset.pricing_param},
                                'location': {'mdm_info_id': str(location_asset.location.mdm_info_id),
                                             'pk': location_asset.location.pk}},
             'total_assignments': 42}
        )
        bulk_assign_location_asset.asset_called_once_with(location_asset, [dep_virtual_server])

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_token")
    def test_sync_dep_virtual_server_devices_task(self, from_dep_token):
        client = Mock()

        serial_number = get_random_string(10).upper()
        client.fetch_devices.return_value = CursorIterator(
            [
                {
                    "device_assigned_date": "2023-01-10T19:09:22Z",
                    "serial_number": serial_number,
                }
            ]
        )
        from_dep_token.return_value = client
        dep_virtual_server = force_dep_virtual_server()

        result = sync_dep_virtual_server_devices_task(dep_virtual_server.pk)
        self.assertEqual(
            result,
            {
                "dep_virtual_server": {
                    "name": dep_virtual_server.name,
                    "pk": dep_virtual_server.pk,
                },
                "operations": {
                    "created": 1,
                    "updated": 0,
                    "unchanged": 0,
                    "marked_deleted": 0,
                },
                "requested_sync_type": "delta_sync",
                "effective_sync_type": "delta_sync",
                "status": "SUCCESS",
            },
        )
        serial_number2 = get_random_string(10).upper()
        client.fetch_devices.return_value = CursorIterator(
            [
                {
                    "device_assigned_date": "2023-01-10T19:09:22Z",
                    "serial_number": serial_number,
                },
                {
                    "device_assigned_date": "2023-01-10T19:09:22Z",
                    "serial_number": serial_number2,
                }
            ]
        )

        result_full = sync_dep_virtual_server_devices_task(dep_virtual_server.pk, force_full_sync=True)
        self.assertEqual(
            result_full,
            {
                "dep_virtual_server": {
                    "name": dep_virtual_server.name,
                    "pk": dep_virtual_server.pk,
                },
                "operations": {
                    # the device of the first synchronization is reported again, unchanged
                    "created": 1,
                    "updated": 0,
                    "unchanged": 1,
                    "marked_deleted": 0,
                },
                "requested_sync_type": "full_sync",
                "effective_sync_type": "full_sync",
                "status": "SUCCESS",
            },
        )

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_token")
    def test_sync_dep_virtual_server_devices_task_error(self, from_dep_token):
        client = Mock()

        client.sync_devices.side_effect = DEPClientError('DEP cursor expired', error_code="EXPIRED_CURSOR")

        serial_number = get_random_string(10).upper()
        client.fetch_devices.return_value = CursorIterator(
            [
                {
                    "device_assigned_date": "2023-01-10T19:09:22Z",
                    "serial_number": serial_number,
                }
            ]
        )

        from_dep_token.return_value = client
        dep_virtual_server = force_dep_virtual_server()
        token = dep_virtual_server.token
        token.sync_cursor = 'yolo-cursor'
        token.save()

        result = sync_dep_virtual_server_devices_task(dep_virtual_server.pk)
        self.assertEqual(
            result,
            {
                "dep_virtual_server": {
                    "name": dep_virtual_server.name,
                    "pk": dep_virtual_server.pk,
                },
                "operations": {
                    "created": 1,
                    "updated": 0,
                    "unchanged": 0,
                    "marked_deleted": 0,
                },
                "requested_sync_type": "delta_sync",
                "effective_sync_type": "full_sync",
                "status": "SUCCESS",
            },
        )

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_token")
    def test_sync_dep_virtual_server_devices_task_reraises_the_other_dep_errors(self, from_dep_token):
        client = Mock()
        client.sync_devices.side_effect = DEPClientError("Could not perform operation", error_code="YOLO")
        from_dep_token.return_value = client
        dep_virtual_server = force_dep_virtual_server()
        token = dep_virtual_server.token
        token.sync_cursor = "yolo-cursor"
        token.save()

        # only an expired cursor is handled, anything else has to surface
        with self.assertRaises(DEPClientError):
            sync_dep_virtual_server_devices_task(dep_virtual_server.pk)
        client.fetch_devices.assert_not_called()

    @patch("zentral.contrib.mdm.tasks.try_lock_dep_virtual_server_sync")
    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_token")
    def test_sync_dep_virtual_server_devices_task_already_running(self, from_dep_token, try_lock):
        try_lock.return_value = False
        dep_virtual_server = force_dep_virtual_server()

        result = sync_dep_virtual_server_devices_task(dep_virtual_server.pk)
        self.assertEqual(
            result,
            {
                "dep_virtual_server": {
                    "name": dep_virtual_server.name,
                    "pk": dep_virtual_server.pk,
                },
                "operations": {
                    "created": 0,
                    "updated": 0,
                    "unchanged": 0,
                    "marked_deleted": 0,
                },
                "requested_sync_type": "delta_sync",
                "effective_sync_type": "delta_sync",
                "status": "SKIPPED",
            },
        )
        # Apple is never contacted
        from_dep_token.assert_not_called()

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_token")
    def test_sync_dep_virtual_server_devices_task_rebuilds_the_event_request(self, from_dep_token, post_event):
        client = Mock()
        serial_number = get_random_string(10).upper()
        client.fetch_devices.return_value = CursorIterator([
            {"device_assigned_date": "2023-01-10T19:09:22Z", "serial_number": serial_number}
        ])
        from_dep_token.return_value = client
        dep_virtual_server = force_dep_virtual_server()

        sync_dep_virtual_server_devices_task(
            dep_virtual_server.pk,
            serialized_event_request={
                "method": "POST",
                "path": "/api/mdm/dep/virtual_servers/1/sync_devices/",
                "ip": "127.0.0.1",
                "user": {"id": 42, "username": "yolo", "email": "yolo@example.com"},
            },
        )

        # the events of a synchronization somebody asked for say who asked for it
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertEqual(event.metadata.request.method, "POST")
        self.assertEqual(event.metadata.request.user.username, "yolo")

    # default enrollment assignment

    @patch("zentral.contrib.mdm.tasks.assign_dep_virtual_server_default_enrollment_task.apply_async")
    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_token")
    def test_sync_dep_virtual_server_devices_task_schedules_the_assignment(self, from_dep_token, apply_async):
        client = Mock()
        client.fetch_devices.return_value = CursorIterator([])
        from_dep_token.return_value = client
        enrollment = force_dep_enrollment(MetaBusinessUnit.objects.create(name=get_random_string(12)))
        dep_virtual_server = enrollment.virtual_server
        dep_virtual_server.default_enrollment = enrollment
        dep_virtual_server.save()

        with self.captureOnCommitCallbacks(execute=True):
            result = sync_dep_virtual_server_devices_task(dep_virtual_server.pk)
        self.assertEqual(result["status"], "SUCCESS")
        apply_async.assert_called_once_with((dep_virtual_server.pk,), {})

    @patch("zentral.contrib.mdm.tasks.assign_dep_virtual_server_default_enrollment_task.apply_async")
    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_token")
    def test_sync_dep_virtual_server_devices_task_passes_the_task_user_on(self, from_dep_token, apply_async):
        client = Mock()
        client.fetch_devices.return_value = CursorIterator([])
        from_dep_token.return_value = client
        enrollment = force_dep_enrollment(MetaBusinessUnit.objects.create(name=get_random_string(12)))
        dep_virtual_server = enrollment.virtual_server
        dep_virtual_server.default_enrollment = enrollment
        dep_virtual_server.save()

        with self.captureOnCommitCallbacks(execute=True):
            sync_dep_virtual_server_devices_task(dep_virtual_server.pk, task_user=42)
        # the assignment shows up in the task list of whoever asked for the synchronization
        apply_async.assert_called_once_with((dep_virtual_server.pk,), {"task_user": 42})

    @patch("zentral.contrib.mdm.tasks.assign_dep_virtual_server_default_enrollment_task.apply_async")
    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_token")
    def test_sync_dep_virtual_server_devices_task_no_default_enrollment_no_assignment(
        self, from_dep_token, apply_async
    ):
        client = Mock()
        client.fetch_devices.return_value = CursorIterator([])
        from_dep_token.return_value = client
        dep_virtual_server = force_dep_virtual_server()

        with self.captureOnCommitCallbacks(execute=True):
            sync_dep_virtual_server_devices_task(dep_virtual_server.pk)
        apply_async.assert_not_called()

    @patch("zentral.contrib.mdm.tasks.assign_dep_virtual_server_default_enrollment")
    def test_assign_dep_virtual_server_default_enrollment_task(self, assign):
        dep_virtual_server = force_dep_virtual_server()
        assign.return_value = {"assigned": 3, "failed": 1}
        self.assertEqual(
            assign_dep_virtual_server_default_enrollment_task(dep_virtual_server.pk),
            {
                "dep_virtual_server": {
                    "name": dep_virtual_server.name,
                    "pk": dep_virtual_server.pk,
                },
                "operations": {"assigned": 3, "failed": 1},
                "status": "SUCCESS",
            },
        )

    @patch("zentral.contrib.mdm.tasks.assign_dep_virtual_server_default_enrollment_task.retry")
    @patch("zentral.contrib.mdm.tasks.try_lock_dep_virtual_server_sync")
    @patch("zentral.contrib.mdm.tasks.assign_dep_virtual_server_default_enrollment")
    def test_assign_dep_virtual_server_default_enrollment_task_already_running_retries(
        self, assign, try_lock, retry
    ):
        try_lock.return_value = False
        retry.side_effect = Retry()
        dep_virtual_server = force_dep_virtual_server()
        # waiting for the next synchronization to schedule this again would delay the assignment
        # by a whole interval, and the work list is derived from the database
        with self.assertRaises(Retry):
            assign_dep_virtual_server_default_enrollment_task(dep_virtual_server.pk)
        assign.assert_not_called()

    @patch("zentral.contrib.mdm.tasks.assign_dep_virtual_server_default_enrollment_task.retry")
    @patch("zentral.contrib.mdm.tasks.try_lock_dep_virtual_server_sync")
    @patch("zentral.contrib.mdm.tasks.assign_dep_virtual_server_default_enrollment")
    def test_assign_dep_virtual_server_default_enrollment_task_skipped_after_the_last_retry(
        self, assign, try_lock, retry
    ):
        try_lock.return_value = False
        retry.side_effect = MaxRetriesExceededError()
        dep_virtual_server = force_dep_virtual_server()
        # the next synchronization schedules it again, so giving up is not losing the work
        result = assign_dep_virtual_server_default_enrollment_task(dep_virtual_server.pk)
        self.assertEqual(result["status"], "SKIPPED")
        self.assertEqual(result["operations"], {"assigned": 0, "failed": 0})
        assign.assert_not_called()

    @patch("zentral.contrib.mdm.tasks.assign_dep_virtual_server_default_enrollment_task.retry")
    @patch("zentral.contrib.mdm.tasks.assign_dep_virtual_server_default_enrollment")
    def test_assign_dep_virtual_server_default_enrollment_task_retries_throttled(self, assign, retry):
        dep_virtual_server = force_dep_virtual_server()
        error = DEPClientError("Too many requests", status_code=429)
        assign.side_effect = error
        retry.side_effect = Retry()
        with self.assertRaises(Retry):
            assign_dep_virtual_server_default_enrollment_task(dep_virtual_server.pk)
        self.assertEqual(retry.call_args.kwargs["exc"], error)

    @patch("zentral.contrib.mdm.tasks.assign_dep_virtual_server_default_enrollment_task.retry")
    @patch("zentral.contrib.mdm.tasks.assign_dep_virtual_server_default_enrollment")
    def test_assign_dep_virtual_server_default_enrollment_task_does_not_retry_rejected(self, assign, retry):
        dep_virtual_server = force_dep_virtual_server()
        assign.side_effect = DEPClientError("Nope", status_code=400)
        with self.assertRaises(DEPClientError):
            assign_dep_virtual_server_default_enrollment_task(dep_virtual_server.pk)
        retry.assert_not_called()

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("zentral.contrib.mdm.software_updates.requests.get")
    def test_sync_software_update(self, get, post_event):
        response_json = Mock()
        response_json.return_value = self.fake_response
        response = Mock()
        response.json = response_json
        get.return_value = response
        result = sync_software_updates_task()
        self.assertEqual(result, {'created': 12, 'deleted': 0, 'present': 0})

import json
import os.path
from unittest.mock import Mock, patch

from django.test import TestCase
from django.utils.crypto import get_random_string

from zentral.contrib.mdm.dep import DEPClientError
from zentral.contrib.mdm.dep_client import CursorIterator
from zentral.contrib.mdm.tasks import (
    bulk_assign_location_asset_task,
    sync_dep_virtual_server_devices_task,
    sync_software_updates_task,
)

from .utils import (
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
                },
                "requested_sync_type": "delta_sync",
                "effective_sync_type": "delta_sync"
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
                    "created": 1,
                    "updated": 1,
                },
                "requested_sync_type": "full_sync",
                "effective_sync_type": "full_sync"
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
                },
                "requested_sync_type": "delta_sync",
                "effective_sync_type": "full_sync"
            },
        )

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

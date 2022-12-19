import datetime
from unittest.mock import patch, Mock
import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.mdm.apps_books import (_sync_asset_d,
                                            _update_assignments,
                                            _update_or_create_asset,
                                            _update_or_create_server_token_asset,
                                            _update_server_token_asset_counts,
                                            associate_server_token_asset,
                                            disassociate_server_token_asset,
                                            sync_asset, sync_assets,
                                            update_server_token_asset_counts)
from zentral.contrib.mdm.events import (AssetCreatedEvent, AssetUpdatedEvent,
                                        DeviceAssignmentCreatedEvent, DeviceAssignmentDeletedEvent,
                                        ServerTokenAssetCreatedEvent, ServerTokenAssetUpdatedEvent)
from zentral.contrib.mdm.models import Asset, DeviceAssignment, ServerToken, ServerTokenAsset
from zentral.core.incidents.models import Severity


class MDMAppsBooksAssetsAssignmentsSyncTestCase(TestCase):

    # tools

    def _force_asset(self):
        return Asset.objects.create(
            adam_id=get_random_string(12),
            pricing_param=get_random_string(12),
            product_type=Asset.ProductType.APP,
            device_assignable=True,
            revocable=True,
            supported_platforms=["iOS", "macOS"]
        )

    def _force_server_token(self):
        server_token = ServerToken(
            token_hash=get_random_string(40, allowed_chars='abcdef0123456789'),
            token=get_random_string(12),
            token_expiration_date=datetime.date(2050, 1, 1),
            organization_name=get_random_string(12),
            country_code="DE",
            library_uid=str(uuid.uuid4()),
            location_name=get_random_string(12),
            platform="enterprisestore",
            website_url="https://business.apple.com",
            mdm_info_id=uuid.uuid4(),
        )
        server_token.set_notification_auth_token()
        server_token.save()
        return server_token

    # _update_or_create_asset

    def test_update_or_create_asset_created(self):
        notification_id = str(uuid.uuid4())
        collected_objects = {}
        events = list(
            _update_or_create_asset(
                "yolo", "fomo",
                {"product_type": Asset.ProductType.APP,
                 "device_assignable": True,
                 "revocable": False,
                 "supported_platforms": ["iOS", "macOS"]},
                notification_id,
                collected_objects
            )
        )
        asset = Asset.objects.get(adam_id="yolo", pricing_param="fomo")
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, AssetCreatedEvent)
        self.assertEqual(event.payload["notification_id"], notification_id)
        self.assertEqual(event.payload["pk"], asset.pk)
        self.assertEqual(event.payload["adam_id"], "yolo")
        self.assertEqual(event.payload["pricing_param"], "fomo")
        self.assertEqual(collected_objects, {"asset": asset})

    def test_update_or_create_asset_noop(self):
        asset = self._force_asset()
        notification_id = str(uuid.uuid4())
        collected_objects = {}
        events = list(
            _update_or_create_asset(
                asset.adam_id, asset.pricing_param,
                {"product_type": asset.product_type,
                 "device_assignable": asset.device_assignable,
                 "revocable": asset.revocable,
                 "supported_platforms": asset.supported_platforms},
                notification_id,
                collected_objects
            )
        )
        self.assertEqual(len(events), 0)
        self.assertEqual(collected_objects, {"asset": asset})

    def test_update_or_create_updated(self):
        asset = self._force_asset()
        notification_id = str(uuid.uuid4())
        collected_objects = {}
        events = list(
            _update_or_create_asset(
                asset.adam_id, asset.pricing_param,
                {"product_type": asset.product_type,
                 "device_assignable": asset.device_assignable,
                 "revocable": asset.revocable,
                 "supported_platforms": ["iOS"]},
                notification_id,
                collected_objects
            )
        )
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, AssetUpdatedEvent)
        self.assertEqual(event.payload["notification_id"], notification_id)
        self.assertEqual(event.payload["pk"], asset.pk)
        self.assertEqual(event.payload["adam_id"], asset.adam_id)
        self.assertEqual(event.payload["pricing_param"], asset.pricing_param)
        self.assertEqual(event.payload["supported_platforms"], ["iOS"])
        asset.refresh_from_db()
        self.assertEqual(asset.supported_platforms, ["iOS"])
        self.assertEqual(collected_objects, {"asset": asset})

    # _update_or_create_server_token_asset

    def test_update_or_create_server_token_asset_created_no_incident(self):
        asset = self._force_asset()
        server_token = self._force_server_token()
        collected_objects = {"asset": asset}
        notification_id = str(uuid.uuid4())
        events = list(
            _update_or_create_server_token_asset(
                server_token,
                {"assigned_count": 0,
                 "available_count": 10,
                 "retired_count": 0,
                 "total_count": 10},
                notification_id, collected_objects
            )
        )
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, ServerTokenAssetCreatedEvent)
        self.assertEqual(
            event.payload,
            {"asset": {"pk": asset.pk, "adam_id": asset.adam_id, "pricing_param": asset.pricing_param},
             "server_token": {"pk": server_token.pk, "mdm_info_id": server_token.mdm_info_id},
             "assigned_count": 0,
             "available_count": 10,
             "retired_count": 0,
             "total_count": 10,
             "notification_id": notification_id}
        )
        server_token_asset = ServerTokenAsset.objects.get(
            server_token=server_token,
            asset=asset
        )
        self.assertEqual(len(event.metadata.incident_updates), 1)
        iu = event.metadata.incident_updates[0]
        self.assertEqual(iu.incident_type, "mdm_asset_availability")
        self.assertEqual(iu.key, {"mdm_sta_pk": server_token_asset.pk})
        self.assertEqual(iu.severity, Severity.NONE)
        self.assertEqual(server_token_asset.assigned_count, 0)
        self.assertEqual(server_token_asset.available_count, 10)
        self.assertEqual(server_token_asset.retired_count, 0)
        self.assertEqual(server_token_asset.total_count, 10)

    def test_update_or_create_server_token_asset_created_minor_incident(self):
        asset = self._force_asset()
        server_token = self._force_server_token()
        collected_objects = {"asset": asset}
        notification_id = str(uuid.uuid4())
        events = list(
            _update_or_create_server_token_asset(
                server_token,
                {"assigned_count": 8,
                 "available_count": 2,
                 "retired_count": 0,
                 "total_count": 10},
                notification_id, collected_objects
            )
        )
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, ServerTokenAssetCreatedEvent)
        self.assertEqual(
            event.payload,
            {"asset": {"pk": asset.pk, "adam_id": asset.adam_id, "pricing_param": asset.pricing_param},
             "server_token": {"pk": server_token.pk, "mdm_info_id": server_token.mdm_info_id},
             "assigned_count": 8,
             "available_count": 2,
             "retired_count": 0,
             "total_count": 10,
             "notification_id": notification_id}
        )
        server_token_asset = ServerTokenAsset.objects.get(
            server_token=server_token,
            asset=asset
        )
        self.assertEqual(len(event.metadata.incident_updates), 1)
        iu = event.metadata.incident_updates[0]
        self.assertEqual(iu.incident_type, "mdm_asset_availability")
        self.assertEqual(iu.key, {"mdm_sta_pk": server_token_asset.pk})
        self.assertEqual(iu.severity, Severity.MINOR)

    def test_update_or_create_server_token_asset_created_major_incident(self):
        asset = self._force_asset()
        server_token = self._force_server_token()
        collected_objects = {"asset": asset}
        notification_id = str(uuid.uuid4())
        events = list(
            _update_or_create_server_token_asset(
                server_token,
                {"assigned_count": 9,
                 "available_count": 1,
                 "retired_count": 0,
                 "total_count": 10},
                notification_id, collected_objects
            )
        )
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, ServerTokenAssetCreatedEvent)
        self.assertEqual(
            event.payload,
            {"asset": {"pk": asset.pk, "adam_id": asset.adam_id, "pricing_param": asset.pricing_param},
             "server_token": {"pk": server_token.pk, "mdm_info_id": server_token.mdm_info_id},
             "assigned_count": 9,
             "available_count": 1,
             "retired_count": 0,
             "total_count": 10,
             "notification_id": notification_id}
        )
        server_token_asset = ServerTokenAsset.objects.get(
            server_token=server_token,
            asset=asset
        )
        self.assertEqual(len(event.metadata.incident_updates), 1)
        iu = event.metadata.incident_updates[0]
        self.assertEqual(iu.incident_type, "mdm_asset_availability")
        self.assertEqual(iu.key, {"mdm_sta_pk": server_token_asset.pk})
        self.assertEqual(iu.severity, Severity.MAJOR)

    def test_update_or_create_server_token_asset_noop(self):
        asset = self._force_asset()
        server_token = self._force_server_token()
        ServerTokenAsset.objects.create(
            server_token=server_token,
            asset=asset,
            assigned_count=0,
            available_count=10,
            retired_count=0,
            total_count=10
        )
        collected_objects = {"asset": asset}
        notification_id = str(uuid.uuid4())
        events = list(
            _update_or_create_server_token_asset(
                server_token,
                {"assigned_count": 0,
                 "available_count": 10,
                 "retired_count": 0,
                 "total_count": 10},
                notification_id, collected_objects
            )
        )
        self.assertEqual(len(events), 0)

    def test_update_or_create_server_token_asset_updated(self):
        asset = self._force_asset()
        server_token = self._force_server_token()
        server_token_asset = ServerTokenAsset.objects.create(
            server_token=server_token,
            asset=asset,
            assigned_count=9,
            available_count=1,
            retired_count=0,
            total_count=10
        )
        collected_objects = {"asset": asset}
        notification_id = str(uuid.uuid4())
        events = list(
            _update_or_create_server_token_asset(
                server_token,
                {"assigned_count": 10,
                 "available_count": 0,
                 "retired_count": 0,
                 "total_count": 10},
                notification_id, collected_objects
            )
        )
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, ServerTokenAssetUpdatedEvent)
        self.assertEqual(
            event.payload,
            {'asset': {'pk': asset.pk, 'adam_id': asset.adam_id, 'pricing_param': asset.pricing_param},
             'server_token': {'pk': server_token.pk, 'mdm_info_id': server_token.mdm_info_id},
             'assigned_count': 10,
             'available_count': 0,
             'retired_count': 0,
             'total_count': 10,
             'notification_id': notification_id}
        )
        self.assertEqual(len(event.metadata.incident_updates), 1)
        iu = event.metadata.incident_updates[0]
        self.assertEqual(iu.incident_type, "mdm_asset_availability")
        self.assertEqual(iu.key, {"mdm_sta_pk": server_token_asset.pk})
        self.assertEqual(iu.severity, Severity.MAJOR)

    # _update_assignments

    def test_update_assignments_noop(self):
        asset = self._force_asset()
        server_token = self._force_server_token()
        server_token_asset = ServerTokenAsset.objects.create(
            server_token=server_token,
            asset=asset,
            assigned_count=3,
            available_count=7,
            retired_count=0,
            total_count=10
        )
        serial_number = get_random_string(12)
        DeviceAssignment.objects.create(
            server_token_asset=server_token_asset,
            serial_number=serial_number
        )
        notification_id = str(uuid.uuid4())
        events = list(
            _update_assignments(
                server_token,
                set([serial_number]),
                notification_id,
                {"asset": asset,
                 "server_token_asset": server_token_asset}
            )
        )
        self.assertEqual(len(events), 0)

    def test_update_assignments_only_remove(self):
        asset = self._force_asset()
        server_token = self._force_server_token()
        server_token_asset = ServerTokenAsset.objects.create(
            server_token=server_token,
            asset=asset,
            assigned_count=3,
            available_count=7,
            retired_count=0,
            total_count=10
        )
        serial_number = get_random_string(12)
        DeviceAssignment.objects.create(
            server_token_asset=server_token_asset,
            serial_number=serial_number
        )
        notification_id = str(uuid.uuid4())
        events = list(
            _update_assignments(
                server_token,
                set(),
                notification_id,
                {"asset": asset,
                 "server_token_asset": server_token_asset}
            )
        )
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, DeviceAssignmentDeletedEvent)
        self.assertEqual(
            event.payload,
            {'asset': {'pk': asset.pk, 'adam_id': asset.adam_id, 'pricing_param': asset.pricing_param},
             'server_token': {'pk': server_token.pk, 'mdm_info_id': server_token.mdm_info_id},
             'assigned_count': 3,
             'available_count': 7,
             'retired_count': 0,
             'total_count': 10,
             'notification_id': notification_id}
        )
        self.assertEqual(event.metadata.machine_serial_number, serial_number)
        self.assertEqual(
            DeviceAssignment.objects.filter(
                server_token_asset=server_token_asset,
                serial_number=serial_number
            ).count(),
            0
        )

    def test_update_assignments_add_and_remove(self):
        asset = self._force_asset()
        server_token = self._force_server_token()
        server_token_asset = ServerTokenAsset.objects.create(
            server_token=server_token,
            asset=asset,
            assigned_count=3,
            available_count=7,
            retired_count=0,
            total_count=10
        )
        removed_serial_number = get_random_string(12)
        DeviceAssignment.objects.create(
            server_token_asset=server_token_asset,
            serial_number=removed_serial_number
        )
        notification_id = str(uuid.uuid4())
        serial_numbers = set([get_random_string(12), get_random_string(12)])
        events = list(
            _update_assignments(
                server_token,
                serial_numbers,
                notification_id,
                {"asset": asset,
                 "server_token_asset": server_token_asset}
            )
        )
        self.assertEqual(len(events), 3)
        event = events[0]
        self.assertIsInstance(event, DeviceAssignmentDeletedEvent)
        self.assertEqual(event.metadata.machine_serial_number, removed_serial_number)
        self.assertEqual(
            DeviceAssignment.objects.filter(
                server_token_asset=server_token_asset,
                serial_number=removed_serial_number
            ).count(),
            0
        )
        for event in events[1:]:
            self.assertIsInstance(event, DeviceAssignmentCreatedEvent)
            self.assertIn(event.metadata.machine_serial_number, serial_numbers)
            self.assertEqual(
                DeviceAssignment.objects.filter(
                    server_token_asset=server_token_asset,
                    serial_number=event.metadata.machine_serial_number
                ).count(),
                1
            )

    # _sync_asset_d

    def test_sync_asset_d(self):
        server_token = self._force_server_token()
        client = Mock()
        asset_name = get_random_string(12)
        bundle_id = "pro.zentral.tests"
        client.get_asset_metadata.return_value = {"name": asset_name, "bundleId": bundle_id}
        serial_number = get_random_string(12)
        client.iter_asset_device_assignments.return_value = [serial_number]
        notification_id = str(uuid.uuid4())
        events = list(
            _sync_asset_d(
                server_token, client,
                {"adamId": "408709785",
                 "assignedCount": 1,
                 "availableCount": 9999,
                 "deviceAssignable": True,
                 "pricingParam": "STDQ",
                 "productType": "App",
                 "retiredCount": 0,
                 "revocable": True,
                 "supportedPlatforms": ["iOS"],
                 "totalCount": 10000},
                notification_id
            )
        )
        self.assertEqual(len(events), 3)
        self.assertIsInstance(events[0], AssetCreatedEvent)
        self.assertIsInstance(events[1], ServerTokenAssetCreatedEvent)
        self.assertIsInstance(events[2], DeviceAssignmentCreatedEvent)
        asset = Asset.objects.get(adam_id="408709785", pricing_param="STDQ")
        self.assertEqual(asset.name, asset_name)
        self.assertEqual(asset.bundle_id, bundle_id)
        client.get_asset_metadata.assert_called_once_with("408709785")
        client.iter_asset_device_assignments.assert_called_once_with("408709785", "STDQ")

    # sync_asset

    def test_sync_asset(self):
        server_token = self._force_server_token()
        client = Mock()
        client.get_asset.return_value = {
            "adamId": "408709785",
            "assignedCount": 1,
            "availableCount": 9999,
            "deviceAssignable": True,
            "pricingParam": "STDQ",
            "productType": "App",
            "retiredCount": 0,
            "revocable": True,
            "supportedPlatforms": ["iOS"],
            "totalCount": 10000,
        }
        asset_name = get_random_string(12)
        bundle_id = "pro.zentral.tests"
        client.get_asset_metadata.return_value = {"name": asset_name, "bundleId": bundle_id}
        serial_number = get_random_string(12)
        client.iter_asset_device_assignments.return_value = [serial_number]
        notification_id = str(uuid.uuid4())
        events = list(sync_asset(server_token, client, "408709785", "STDQ", notification_id))
        self.assertEqual(len(events), 3)

    def test_sync_asset_unknown_asset(self):
        server_token = self._force_server_token()
        client = Mock()
        client.get_asset.return_value = None
        notification_id = str(uuid.uuid4())
        events = list(sync_asset(server_token, client, "408709785", "STDQ", notification_id))
        self.assertEqual(len(events), 0)
        client.get_asset.assert_called_once_with('408709785', 'STDQ')

    # sync_assets

    @patch("zentral.contrib.mdm.apps_books.AppsBooksClient")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_sync_assets(self, post_event, AppsBooksClient):
        server_token = self._force_server_token()
        client = Mock()
        AppsBooksClient.from_server_token.return_value = client
        client.iter_assets.return_value = [
            {"adamId": "408709785",
             "assignedCount": 1,
             "availableCount": 9999,
             "deviceAssignable": True,
             "pricingParam": "STDQ",
             "productType": "App",
             "retiredCount": 0,
             "revocable": True,
             "supportedPlatforms": ["iOS"],
             "totalCount": 10000}
        ]
        asset_name = get_random_string(12)
        bundle_id = "pro.zentral.tests"
        client.get_asset_metadata.return_value = {"name": asset_name, "bundleId": bundle_id}
        serial_number = get_random_string(12)
        client.iter_asset_device_assignments.return_value = [serial_number]
        sync_assets(server_token)
        self.assertEqual(len(post_event.call_args_list), 3)

    # _update_server_token_asset_counts

    def test_update_server_token_asset_counts_noop(self):
        asset = self._force_asset()
        server_token = self._force_server_token()
        server_token_asset = ServerTokenAsset.objects.create(
            server_token=server_token,
            asset=asset,
            assigned_count=3,
            available_count=7,
            retired_count=0,
            total_count=10
        )
        notification_id = str(uuid.uuid4())
        events = list(_update_server_token_asset_counts(server_token_asset, {"available_count": 0}, notification_id))
        self.assertEqual(len(events), 0)

    def test_update_server_token_asset_negative_counts_value_error(self):
        asset = self._force_asset()
        server_token = self._force_server_token()
        server_token_asset = ServerTokenAsset.objects.create(
            server_token=server_token,
            asset=asset,
            assigned_count=0,
            available_count=0,
            retired_count=0,
            total_count=0
        )
        notification_id = str(uuid.uuid4())
        with self.assertRaises(ValueError):
            list(
                _update_server_token_asset_counts(
                    server_token_asset,
                    {"available_count": -1,
                     "total_count": -1},
                    notification_id)
            )

    def test_update_server_token_asset_assign_count_value_error(self):
        asset = self._force_asset()
        server_token = self._force_server_token()
        server_token_asset = ServerTokenAsset.objects.create(
            server_token=server_token,
            asset=asset,
            assigned_count=0,
            available_count=0,
            retired_count=0,
            total_count=0
        )
        notification_id = str(uuid.uuid4())
        with self.assertRaises(ValueError):
            list(
                _update_server_token_asset_counts(
                    server_token_asset,
                    {"assigned_count": 1},
                    notification_id)
            )

    def test_update_server_token_asset_available_count_value_error(self):
        asset = self._force_asset()
        server_token = self._force_server_token()
        server_token_asset = ServerTokenAsset.objects.create(
            server_token=server_token,
            asset=asset,
            assigned_count=0,
            available_count=0,
            retired_count=0,
            total_count=0
        )
        notification_id = str(uuid.uuid4())
        with self.assertRaises(ValueError):
            list(
                _update_server_token_asset_counts(
                    server_token_asset,
                    {"available_count": 1},
                    notification_id)
            )

    def test_update_server_token_asset_counts(self):
        asset = self._force_asset()
        server_token = self._force_server_token()
        server_token_asset = ServerTokenAsset.objects.create(
            server_token=server_token,
            asset=asset,
            assigned_count=10,
            available_count=0,
            retired_count=0,
            total_count=10
        )
        notification_id = str(uuid.uuid4())
        events = list(
            _update_server_token_asset_counts(
                server_token_asset,
                {"total_count": 1,
                 "available_count": 1},
                notification_id
            )
        )
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, ServerTokenAssetUpdatedEvent)
        self.assertEqual(
            event.payload,
            {'asset': {'pk': asset.pk, 'adam_id': asset.adam_id, 'pricing_param': asset.pricing_param},
             'server_token': {'pk': server_token.pk, 'mdm_info_id': server_token.mdm_info_id},
             'assigned_count': 10,
             'available_count': 1,
             'retired_count': 0,
             'total_count': 11,
             'notification_id': notification_id}
        )
        server_token_asset.refresh_from_db()
        self.assertEqual(server_token_asset.available_count, 1)
        self.assertEqual(server_token_asset.total_count, 11)

    # update_server_token_asset_counts

    def test_update_server_token_asset_counts_ok(self):
        asset = self._force_asset()
        server_token = self._force_server_token()
        server_token_asset = ServerTokenAsset.objects.create(
            server_token=server_token,
            asset=asset,
            assigned_count=10,
            available_count=0,
            retired_count=0,
            total_count=10
        )
        client = Mock()
        notification_id = str(uuid.uuid4())
        events = list(
            update_server_token_asset_counts(
                server_token, client,
                asset.adam_id, asset.pricing_param,
                {"total_count": 1,
                 "available_count": 1},
                notification_id
            )
        )
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, ServerTokenAssetUpdatedEvent)
        server_token_asset.refresh_from_db()
        self.assertEqual(server_token_asset.available_count, 1)
        self.assertEqual(server_token_asset.total_count, 11)

    def test_update_server_token_asset_counts_sync_required(self):
        asset = self._force_asset()
        server_token = self._force_server_token()
        server_token_asset = ServerTokenAsset.objects.create(
            server_token=server_token,
            asset=asset,
            assigned_count=10,
            available_count=0,
            retired_count=0,
            total_count=10
        )
        client = Mock()
        client.get_asset.return_value = {
            "adamId": asset.adam_id,
            "assignedCount": 9,
            "availableCount": 0,
            "deviceAssignable": True,
            "pricingParam": asset.pricing_param,
            "productType": "App",
            "retiredCount": 0,
            "revocable": True,
            "supportedPlatforms": ["iOS", "macOS"],
            "totalCount": 9,
        }
        asset_name = get_random_string(12)
        bundle_id = "pro.zentral.tests"
        client.get_asset_metadata.return_value = {"name": asset_name, "bundleId": bundle_id}
        serial_number = get_random_string(12)
        client.iter_asset_device_assignments.return_value = [serial_number]
        notification_id = str(uuid.uuid4())
        events = list(
            update_server_token_asset_counts(
                server_token, client,
                asset.adam_id, asset.pricing_param,
                {"total_count": -1,
                 "available_count": -1},
                notification_id
            )
        )
        self.assertEqual(len(events), 3)
        event = events[1]
        self.assertIsInstance(event, ServerTokenAssetUpdatedEvent)
        server_token_asset.refresh_from_db()
        self.assertEqual(server_token_asset.available_count, 0)
        self.assertEqual(server_token_asset.total_count, 9)
        client.get_asset.assert_called_once_with(asset.adam_id, asset.pricing_param)

    # associate_server_token_asset

    @patch("zentral.contrib.mdm.apps_books.queue_install_application_command_if_necessary")
    def test_associate_server_token_asset(self, queue_install_application_command_if_necessary):
        asset = self._force_asset()
        server_token = self._force_server_token()
        server_token_asset = ServerTokenAsset.objects.create(
            server_token=server_token,
            asset=asset,
            assigned_count=10,
            available_count=1,
            retired_count=0,
            total_count=11
        )
        client = Mock()
        event_id = str(uuid.uuid4())
        notification_id = str(uuid.uuid4())
        serial_number = get_random_string(12)
        events = list(
            associate_server_token_asset(
                server_token, client,
                asset.adam_id, asset.pricing_param,
                [serial_number],
                event_id, notification_id
            )
        )
        self.assertEqual(len(events), 2)
        event = events[0]
        self.assertIsInstance(event, DeviceAssignmentCreatedEvent)
        self.assertEqual(event.metadata.machine_serial_number, serial_number)
        self.assertEqual(
            DeviceAssignment.objects.filter(
                server_token_asset=server_token_asset,
                serial_number=serial_number
            ).count(),
            1
        )
        event = events[1]
        self.assertIsInstance(event, ServerTokenAssetUpdatedEvent)
        server_token_asset.refresh_from_db()
        self.assertEqual(server_token_asset.assigned_count, 11)
        self.assertEqual(server_token_asset.available_count, 0)
        queue_install_application_command_if_necessary.assert_called_once_with(
            server_token, serial_number, asset.adam_id, asset.pricing_param
        )

    def test_associate_server_token_asset_unknown_server_token_asset(self):
        server_token = self._force_server_token()
        client = Mock()
        client.get_asset.return_value = {
            "adamId": "408709785",
            "assignedCount": 9,
            "availableCount": 0,
            "deviceAssignable": True,
            "pricingParam": "STDQ",
            "productType": "App",
            "retiredCount": 0,
            "revocable": True,
            "supportedPlatforms": ["iOS", "macOS"],
            "totalCount": 9,
        }
        asset_name = get_random_string(12)
        bundle_id = "pro.zentral.tests"
        client.get_asset_metadata.return_value = {"name": asset_name, "bundleId": bundle_id}
        serial_number = get_random_string(12)
        client.iter_asset_device_assignments.return_value = [serial_number]
        event_id = str(uuid.uuid4())
        notification_id = str(uuid.uuid4())
        events = list(
            associate_server_token_asset(
                server_token, client,
                "408709785", "STDQ",
                [serial_number],
                event_id, notification_id
            )
        )
        self.assertEqual(len(events), 3)
        self.assertEqual(Asset.objects.filter(adam_id="408709785", pricing_param="STDQ").count(), 1)
        server_token_asset = ServerTokenAsset.objects.get(
            asset__adam_id="408709785",
            asset__pricing_param="STDQ",
            server_token=server_token
        )
        self.assertEqual(server_token_asset.assigned_count, 9)
        self.assertEqual(server_token_asset.total_count, 9)
        self.assertEqual(
            DeviceAssignment.objects.filter(
                server_token_asset=server_token_asset,
                serial_number=serial_number
            ).count(),
            1
        )

    def test_associate_server_token_asset_bad_counts(self):
        asset = self._force_asset()
        server_token = self._force_server_token()
        ServerTokenAsset.objects.create(
            server_token=server_token,
            asset=asset,
            assigned_count=11,
            available_count=0,
            retired_count=0,
            total_count=11
        )
        client = Mock()
        client.get_asset.return_value = {
            "adamId": asset.adam_id,
            "assignedCount": 12,
            "availableCount": 0,
            "deviceAssignable": True,
            "pricingParam": asset.pricing_param,
            "productType": "App",
            "retiredCount": 0,
            "revocable": True,
            "supportedPlatforms": ["iOS", "macOS"],
            "totalCount": 12,
        }
        asset_name = get_random_string(12)
        bundle_id = "pro.zentral.tests"
        client.get_asset_metadata.return_value = {"name": asset_name, "bundleId": bundle_id}
        serial_number = get_random_string(12)
        client.iter_asset_device_assignments.return_value = [serial_number]
        event_id = str(uuid.uuid4())
        notification_id = str(uuid.uuid4())
        events = list(
            associate_server_token_asset(
                server_token, client,
                asset.adam_id, asset.pricing_param,
                [serial_number],
                event_id, notification_id
            )
        )
        self.assertEqual(len(events), 3)
        self.assertIsInstance(events[0], DeviceAssignmentCreatedEvent)
        self.assertIsInstance(events[1], AssetUpdatedEvent)
        self.assertIsInstance(events[2], ServerTokenAssetUpdatedEvent)

    # disassociate_server_token_asset

    @patch("zentral.contrib.mdm.apps_books.clear_on_the_fly_assignment")
    def test_disassociate_server_token_asset(self, clear_on_the_fly_assignment):
        asset = self._force_asset()
        server_token = self._force_server_token()
        server_token_asset = ServerTokenAsset.objects.create(
            server_token=server_token,
            asset=asset,
            assigned_count=10,
            available_count=1,
            retired_count=0,
            total_count=11
        )
        client = Mock()
        event_id = str(uuid.uuid4())
        notification_id = str(uuid.uuid4())
        serial_number = get_random_string(12)
        DeviceAssignment.objects.create(server_token_asset=server_token_asset, serial_number=serial_number)
        events = list(
            disassociate_server_token_asset(
                server_token, client,
                asset.adam_id, asset.pricing_param,
                [serial_number],
                event_id, notification_id
            )
        )
        self.assertEqual(len(events), 2)
        event = events[0]
        self.assertIsInstance(event, DeviceAssignmentDeletedEvent)
        self.assertEqual(event.metadata.machine_serial_number, serial_number)
        self.assertEqual(
            DeviceAssignment.objects.filter(
                server_token_asset=server_token_asset,
                serial_number=serial_number
            ).count(),
            0
        )
        event = events[1]
        self.assertIsInstance(event, ServerTokenAssetUpdatedEvent)
        server_token_asset.refresh_from_db()
        self.assertEqual(server_token_asset.assigned_count, 9)
        self.assertEqual(server_token_asset.available_count, 2)
        clear_on_the_fly_assignment.assert_called_once_with(
            server_token, serial_number, asset.adam_id, asset.pricing_param, "disassociate success"
        )

    def test_disassociate_server_token_unknown_asset(self):
        server_token = self._force_server_token()
        client = Mock()
        client.get_asset.return_value = {
            "adamId": "408709785",
            "assignedCount": 9,
            "availableCount": 0,
            "deviceAssignable": True,
            "pricingParam": "STDQ",
            "productType": "App",
            "retiredCount": 0,
            "revocable": True,
            "supportedPlatforms": ["iOS", "macOS"],
            "totalCount": 9,
        }
        asset_name = get_random_string(12)
        bundle_id = "pro.zentral.tests"
        client.get_asset_metadata.return_value = {"name": asset_name, "bundleId": bundle_id}
        serial_number = get_random_string(12)
        client.iter_asset_device_assignments.return_value = []
        event_id = str(uuid.uuid4())
        notification_id = str(uuid.uuid4())
        events = list(
            disassociate_server_token_asset(
                server_token, client,
                "408709785", "STDQ",
                [serial_number],
                event_id, notification_id
            )
        )
        self.assertEqual(len(events), 2)
        self.assertIsInstance(events[0], AssetCreatedEvent)
        self.assertIsInstance(events[1], ServerTokenAssetCreatedEvent)
        self.assertEqual(Asset.objects.filter(adam_id="408709785", pricing_param="STDQ").count(), 1)
        server_token_asset = ServerTokenAsset.objects.get(
            asset__adam_id="408709785",
            asset__pricing_param="STDQ",
            server_token=server_token
        )
        self.assertEqual(server_token_asset.assigned_count, 9)
        self.assertEqual(server_token_asset.total_count, 9)
        self.assertEqual(
            DeviceAssignment.objects.filter(
                server_token_asset=server_token_asset,
                serial_number=serial_number
            ).count(),
            0
        )

    def test_disassociate_server_token_bad_counts(self):
        asset = self._force_asset()
        server_token = self._force_server_token()
        server_token_asset = ServerTokenAsset.objects.create(
            server_token=server_token,
            asset=asset,
            assigned_count=0,
            available_count=0,
            retired_count=0,
            total_count=11
        )
        client = Mock()
        client.get_asset.return_value = {
            "adamId": asset.adam_id,
            "assignedCount": 0,
            "availableCount": 0,
            "deviceAssignable": True,
            "pricingParam": asset.pricing_param,
            "productType": "App",
            "retiredCount": 0,
            "revocable": True,
            "supportedPlatforms": ["iOS", "macOS"],
            "totalCount": 11,
        }
        asset_name = get_random_string(12)
        bundle_id = "pro.zentral.tests"
        client.get_asset_metadata.return_value = {"name": asset_name, "bundleId": bundle_id}
        serial_number = get_random_string(12)
        DeviceAssignment.objects.create(server_token_asset=server_token_asset, serial_number=serial_number)
        client.iter_asset_device_assignments.return_value = []
        event_id = str(uuid.uuid4())
        notification_id = str(uuid.uuid4())
        events = list(
            disassociate_server_token_asset(
                server_token, client,
                asset.adam_id, asset.pricing_param,
                [serial_number],
                event_id, notification_id
            )
        )
        self.assertEqual(len(events), 2)
        self.assertIsInstance(events[0], DeviceAssignmentDeletedEvent)
        self.assertIsInstance(events[1], AssetUpdatedEvent)

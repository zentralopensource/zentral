from unittest.mock import call, patch, Mock
import uuid
from django.core.cache import cache
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.mdm.apps_books import (_sync_asset_d,
                                            _update_assignments,
                                            _update_or_create_asset,
                                            _update_or_create_location_asset,
                                            _update_location_asset_counts,
                                            AppsBooksAPIError,
                                            associate_location_asset,
                                            bulk_assign_location_asset,
                                            disassociate_location_asset,
                                            ensure_client_config,
                                            ensure_target_asset_assignments,
                                            get_otf_association_cache_key,
                                            iter_location_assets_to_refresh,
                                            location_cache,
                                            refresh_asset_metadata,
                                            sync_asset, sync_assets, sync_unlimited_assets,
                                            update_location_asset_counts)
from zentral.contrib.mdm.events import (AssetCreatedEvent, AssetUpdatedEvent,
                                        DeviceAssignmentCreatedEvent, DeviceAssignmentDeletedEvent,
                                        LocationAssetCreatedEvent, LocationAssetUpdatedEvent)
from zentral.contrib.mdm.models import (Asset, DEPDevice, DeviceAssignment, Location, LocationAsset,
                                        hash_location_notification_auth_token)
from zentral.core.incidents.models import Severity
from .utils import force_asset, force_dep_device, force_location, force_location_asset


class MDMAppsBooksAssetsAssignmentsSyncTestCase(TestCase):

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
        self.assertEqual(event.payload["asset"]["pk"], asset.pk)
        self.assertEqual(event.payload["asset"]["adam_id"], "yolo")
        self.assertEqual(event.payload["asset"]["pricing_param"], "fomo")
        self.assertEqual(
            event.get_linked_objects_keys(),
            {"mdm_asset": [("yolo", "fomo")]}
        )
        self.assertEqual(collected_objects, {"asset": asset})

    def test_update_or_create_asset_noop(self):
        asset = force_asset()
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

    def test_update_or_create_asset_updated(self):
        asset = force_asset()
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
        self.assertEqual(event.payload["asset"]["pk"], asset.pk)
        self.assertEqual(event.payload["asset"]["adam_id"], asset.adam_id)
        self.assertEqual(event.payload["asset"]["pricing_param"], asset.pricing_param)
        self.assertEqual(event.payload["asset"]["supported_platforms"], ["iOS"])
        self.assertEqual(
            event.get_linked_objects_keys(),
            {"mdm_asset": [(asset.adam_id, asset.pricing_param)]}
        )
        asset.refresh_from_db()
        self.assertEqual(asset.supported_platforms, ["iOS"])
        self.assertEqual(collected_objects, {"asset": asset})

    # _update_or_create_location_asset

    def test_update_or_create_location_asset_created_no_incident(self):
        asset = force_asset()
        location = force_location()
        collected_objects = {"asset": asset}
        notification_id = str(uuid.uuid4())
        events = list(
            _update_or_create_location_asset(
                location,
                {"assigned_count": 0,
                 "available_count": 10,
                 "retired_count": 0,
                 "total_count": 10},
                notification_id, collected_objects
            )
        )
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, LocationAssetCreatedEvent)
        self.assertEqual(
            event.payload,
            {"asset": {"pk": asset.pk, "adam_id": asset.adam_id, "pricing_param": asset.pricing_param},
             "location": {"pk": location.pk, "mdm_info_id": str(location.mdm_info_id)},
             "assigned_count": 0,
             "available_count": 10,
             "retired_count": 0,
             "total_count": 10,
             "notification_id": notification_id}
        )
        location_asset = LocationAsset.objects.get(
            location=location,
            asset=asset
        )
        self.assertEqual(len(event.metadata.incident_updates), 1)
        iu = event.metadata.incident_updates[0]
        self.assertEqual(iu.incident_type, "mdm_asset_availability")
        self.assertEqual(iu.key, {"mdm_la_pk": location_asset.pk})
        self.assertEqual(iu.severity, Severity.NONE)
        self.assertEqual(location_asset.assigned_count, 0)
        self.assertEqual(location_asset.available_count, 10)
        self.assertEqual(location_asset.retired_count, 0)
        self.assertEqual(location_asset.total_count, 10)

    def test_update_or_create_location_asset_created_minor_incident(self):
        asset = force_asset()
        location = force_location()
        collected_objects = {"asset": asset}
        notification_id = str(uuid.uuid4())
        events = list(
            _update_or_create_location_asset(
                location,
                {"assigned_count": 8,
                 "available_count": 2,
                 "retired_count": 0,
                 "total_count": 10},
                notification_id, collected_objects
            )
        )
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, LocationAssetCreatedEvent)
        self.assertEqual(
            event.payload,
            {"asset": {"pk": asset.pk, "adam_id": asset.adam_id, "pricing_param": asset.pricing_param},
             "location": {"pk": location.pk, "mdm_info_id": str(location.mdm_info_id)},
             "assigned_count": 8,
             "available_count": 2,
             "retired_count": 0,
             "total_count": 10,
             "notification_id": notification_id}
        )
        location_asset = LocationAsset.objects.get(
            location=location,
            asset=asset
        )
        self.assertEqual(len(event.metadata.incident_updates), 1)
        iu = event.metadata.incident_updates[0]
        self.assertEqual(iu.incident_type, "mdm_asset_availability")
        self.assertEqual(iu.key, {"mdm_la_pk": location_asset.pk})
        self.assertEqual(iu.severity, Severity.MINOR)

    def test_update_or_create_location_asset_created_major_incident(self):
        asset = force_asset()
        location = force_location()
        collected_objects = {"asset": asset}
        notification_id = str(uuid.uuid4())
        events = list(
            _update_or_create_location_asset(
                location,
                {"assigned_count": 9,
                 "available_count": 1,
                 "retired_count": 0,
                 "total_count": 10},
                notification_id, collected_objects
            )
        )
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, LocationAssetCreatedEvent)
        self.assertEqual(
            event.payload,
            {"asset": {"pk": asset.pk, "adam_id": asset.adam_id, "pricing_param": asset.pricing_param},
             "location": {"pk": location.pk, "mdm_info_id": str(location.mdm_info_id)},
             "assigned_count": 9,
             "available_count": 1,
             "retired_count": 0,
             "total_count": 10,
             "notification_id": notification_id}
        )
        location_asset = LocationAsset.objects.get(
            location=location,
            asset=asset
        )
        self.assertEqual(len(event.metadata.incident_updates), 1)
        iu = event.metadata.incident_updates[0]
        self.assertEqual(iu.incident_type, "mdm_asset_availability")
        self.assertEqual(iu.key, {"mdm_la_pk": location_asset.pk})
        self.assertEqual(iu.severity, Severity.MAJOR)

    def test_update_or_create_location_asset_noop(self):
        asset = force_asset()
        location = force_location()
        LocationAsset.objects.create(
            location=location,
            asset=asset,
            assigned_count=0,
            available_count=10,
            retired_count=0,
            total_count=10
        )
        collected_objects = {"asset": asset}
        notification_id = str(uuid.uuid4())
        events = list(
            _update_or_create_location_asset(
                location,
                {"assigned_count": 0,
                 "available_count": 10,
                 "retired_count": 0,
                 "total_count": 10},
                notification_id, collected_objects
            )
        )
        self.assertEqual(len(events), 0)

    def test_update_or_create_location_asset_updated(self):
        asset = force_asset()
        location = force_location()
        location_asset = LocationAsset.objects.create(
            location=location,
            asset=asset,
            assigned_count=9,
            available_count=1,
            retired_count=0,
            total_count=10
        )
        collected_objects = {"asset": asset}
        notification_id = str(uuid.uuid4())
        events = list(
            _update_or_create_location_asset(
                location,
                {"assigned_count": 10,
                 "available_count": 0,
                 "retired_count": 0,
                 "total_count": 10},
                notification_id, collected_objects
            )
        )
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, LocationAssetUpdatedEvent)
        self.assertEqual(
            event.payload,
            {'asset': {'pk': asset.pk, 'adam_id': asset.adam_id, 'pricing_param': asset.pricing_param},
             'location': {'pk': location.pk, 'mdm_info_id': str(location.mdm_info_id)},
             'assigned_count': 10,
             'available_count': 0,
             'retired_count': 0,
             'total_count': 10,
             'notification_id': notification_id}
        )
        self.assertEqual(len(event.metadata.incident_updates), 1)
        iu = event.metadata.incident_updates[0]
        self.assertEqual(iu.incident_type, "mdm_asset_availability")
        self.assertEqual(iu.key, {"mdm_la_pk": location_asset.pk})
        self.assertEqual(iu.severity, Severity.MAJOR)

    # _update_assignments

    def test_update_assignments_noop(self):
        asset = force_asset()
        location = force_location()
        location_asset = LocationAsset.objects.create(
            location=location,
            asset=asset,
            assigned_count=3,
            available_count=7,
            retired_count=0,
            total_count=10
        )
        serial_number = get_random_string(12)
        DeviceAssignment.objects.create(
            location_asset=location_asset,
            serial_number=serial_number
        )
        notification_id = str(uuid.uuid4())
        events = list(
            _update_assignments(
                location,
                set([serial_number]),
                notification_id,
                {"asset": asset,
                 "location_asset": location_asset}
            )
        )
        self.assertEqual(len(events), 0)

    def test_update_assignments_only_remove(self):
        asset = force_asset()
        location = force_location()
        location_asset = LocationAsset.objects.create(
            location=location,
            asset=asset,
            assigned_count=3,
            available_count=7,
            retired_count=0,
            total_count=10
        )
        serial_number = get_random_string(12)
        DeviceAssignment.objects.create(
            location_asset=location_asset,
            serial_number=serial_number
        )
        notification_id = str(uuid.uuid4())
        events = list(
            _update_assignments(
                location,
                set(),
                notification_id,
                {"asset": asset,
                 "location_asset": location_asset}
            )
        )
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, DeviceAssignmentDeletedEvent)
        self.assertEqual(
            event.payload,
            {'asset': {'pk': asset.pk, 'adam_id': asset.adam_id, 'pricing_param': asset.pricing_param},
             'location': {'pk': location.pk, 'mdm_info_id': str(location.mdm_info_id)},
             'assigned_count': 3,
             'available_count': 7,
             'retired_count': 0,
             'total_count': 10,
             'notification_id': notification_id}
        )
        self.assertEqual(event.metadata.machine_serial_number, serial_number)
        self.assertEqual(
            DeviceAssignment.objects.filter(
                location_asset=location_asset,
                serial_number=serial_number
            ).count(),
            0
        )

    def test_update_assignments_add_and_remove(self):
        asset = force_asset()
        location = force_location()
        location_asset = LocationAsset.objects.create(
            location=location,
            asset=asset,
            assigned_count=3,
            available_count=7,
            retired_count=0,
            total_count=10
        )
        removed_serial_number = get_random_string(12)
        DeviceAssignment.objects.create(
            location_asset=location_asset,
            serial_number=removed_serial_number
        )
        notification_id = str(uuid.uuid4())
        serial_numbers = set([get_random_string(12), get_random_string(12)])
        events = list(
            _update_assignments(
                location,
                serial_numbers,
                notification_id,
                {"asset": asset,
                 "location_asset": location_asset}
            )
        )
        self.assertEqual(len(events), 3)
        event = events[0]
        self.assertIsInstance(event, DeviceAssignmentDeletedEvent)
        self.assertEqual(event.metadata.machine_serial_number, removed_serial_number)
        self.assertEqual(
            DeviceAssignment.objects.filter(
                location_asset=location_asset,
                serial_number=removed_serial_number
            ).count(),
            0
        )
        for event in events[1:]:
            self.assertIsInstance(event, DeviceAssignmentCreatedEvent)
            self.assertIn(event.metadata.machine_serial_number, serial_numbers)
            self.assertEqual(
                DeviceAssignment.objects.filter(
                    location_asset=location_asset,
                    serial_number=event.metadata.machine_serial_number
                ).count(),
                1
            )

    # _sync_asset_d

    def test_sync_asset_d(self):
        location = force_location()
        client = Mock()
        asset_name = get_random_string(12)
        bundle_id = "pro.zentral.tests"
        client.get_asset_metadata.return_value = {"name": asset_name, "bundleId": bundle_id}
        serial_number = get_random_string(12)
        client.iter_asset_device_assignments.return_value = [serial_number]
        notification_id = str(uuid.uuid4())
        events = list(
            _sync_asset_d(
                location, client,
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
        self.assertIsInstance(events[1], LocationAssetCreatedEvent)
        self.assertIsInstance(events[2], DeviceAssignmentCreatedEvent)
        asset = Asset.objects.get(adam_id="408709785", pricing_param="STDQ")
        self.assertEqual(asset.name, asset_name)
        self.assertEqual(asset.bundle_id, bundle_id)
        client.get_asset_metadata.assert_called_once_with("408709785")
        client.iter_asset_device_assignments.assert_called_once_with("408709785", "STDQ")

    # sync_asset

    def test_sync_asset(self):
        location = force_location()
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
        events = list(sync_asset(location, client, "408709785", "STDQ", notification_id))
        self.assertEqual(len(events), 3)

    def test_sync_asset_unknown_asset(self):
        location = force_location()
        client = Mock()
        client.get_asset.return_value = None
        notification_id = str(uuid.uuid4())
        events = list(sync_asset(location, client, "408709785", "STDQ", notification_id))
        self.assertEqual(len(events), 0)
        client.get_asset.assert_called_once_with('408709785', 'STDQ')

    # sync_assets

    @patch("zentral.contrib.mdm.apps_books.AppsBooksClient")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_sync_assets(self, post_event, AppsBooksClient):
        location = force_location()
        client, _ = self._get_client_config_client(location)
        AppsBooksClient.from_location.return_value = client
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
        sync_assets(location)
        self.assertEqual(len(post_event.call_args_list), 3)
        client.update_client_config.assert_not_called()

    @patch("zentral.contrib.mdm.apps_books.logger.exception")
    @patch("zentral.contrib.mdm.apps_books.AppsBooksClient")
    def test_sync_assets_client_config_error(self, AppsBooksClient, logger_exception):
        location = force_location()
        client = Mock()
        client.get_client_config.side_effect = AppsBooksAPIError("Invalid server token")
        client.iter_assets.return_value = []
        AppsBooksClient.from_location.return_value = client
        sync_assets(location)
        logger_exception.assert_called_once_with("Location %s: could not check the client config", location.name)
        client.iter_assets.assert_called_once_with()

    # ensure_client_config

    def _get_client_config_client(self, location, **config):
        notification_auth_token = location.set_notification_auth_token()
        location.save()
        notification_url = f"https://zentral/public/mdm/locations/{location.mdm_info_id}/notify/"
        client = Mock()
        client.mdm_info_id = str(location.mdm_info_id)
        client.get_notification_url.return_value = notification_url
        client.get_notification_types.return_value = ["ASSET_COUNT", "ASSET_MANAGEMENT", "UNLIMITED_ASSET"]
        client_config = {
            "mdmInfo": {"id": str(location.mdm_info_id)},
            "notificationAuthToken": notification_auth_token,
            "notificationUrl": notification_url,
            "subscribedNotificationTypes": ["UNLIMITED_ASSET", "ASSET_MANAGEMENT", "ASSET_COUNT"],
        }
        client_config.update(config)
        client.get_client_config.return_value = {k: v for k, v in client_config.items() if v is not None}
        return client, notification_auth_token

    def test_ensure_client_config_ok(self):
        location = force_location()
        client, _ = self._get_client_config_client(location)
        notification_auth_token_hash = location.notification_auth_token_hash
        self.assertFalse(ensure_client_config(location, client))
        client.get_client_config.assert_called_once_with(verify_mdm_info=False)
        client.update_client_config.assert_not_called()
        location.refresh_from_db()
        self.assertEqual(location.notification_auth_token_hash, notification_auth_token_hash)

    @patch("zentral.contrib.mdm.apps_books.logger.error")
    def test_ensure_client_config_other_mdm(self, logger_error):
        location = force_location()
        client, _ = self._get_client_config_client(location, mdmInfo={"id": str(uuid.uuid4())},
                                                   subscribedNotificationTypes=["ASSET_COUNT"])
        self.assertFalse(ensure_client_config(location, client))
        client.update_client_config.assert_not_called()
        logger_error.assert_called_once_with("Location %s: client config of another MDM, not updated", location.name)

    def test_ensure_client_config_missing_notification_type(self):
        location = force_location()
        client, notification_auth_token = self._get_client_config_client(
            location, subscribedNotificationTypes=["ASSET_MANAGEMENT", "ASSET_COUNT"]
        )
        notification_auth_token_hash = location.notification_auth_token_hash
        with self.assertLogs("zentral.contrib.mdm.apps_books", "INFO") as cm:
            self.assertTrue(ensure_client_config(location, client))
        self.assertEqual(cm.output, [f"INFO:zentral.contrib.mdm.apps_books:Location {location.name}: "
                                     "update client config"])
        client.update_client_config.assert_called_once_with(notification_auth_token)
        location.refresh_from_db()
        self.assertEqual(location.notification_auth_token_hash, notification_auth_token_hash)

    def test_ensure_client_config_no_notification_types(self):
        location = force_location()
        client, notification_auth_token = self._get_client_config_client(location, subscribedNotificationTypes=None)
        self.assertTrue(ensure_client_config(location, client))
        client.update_client_config.assert_called_once_with(notification_auth_token)

    def test_ensure_client_config_bad_notification_url(self):
        location = force_location()
        client, notification_auth_token = self._get_client_config_client(
            location, notificationUrl="https://example.com/notify/"
        )
        self.assertTrue(ensure_client_config(location, client))
        client.update_client_config.assert_called_once_with(notification_auth_token)

    def test_ensure_client_config_bad_notification_auth_token(self):
        location = force_location()
        client, notification_auth_token = self._get_client_config_client(
            location, notificationAuthToken=get_random_string(12)
        )
        notification_auth_token_hash = location.notification_auth_token_hash
        # changed in the database during the check, must not be overwritten
        new_name = get_random_string(12)
        Location.objects.filter(pk=location.pk).update(name=new_name)
        self.assertTrue(ensure_client_config(location, client))
        client.update_client_config.assert_called_once()
        new_notification_auth_token = client.update_client_config.call_args.args[0]
        self.assertNotEqual(new_notification_auth_token, notification_auth_token)
        location.refresh_from_db()
        self.assertEqual(location.name, new_name)
        self.assertNotEqual(location.notification_auth_token_hash, notification_auth_token_hash)
        self.assertEqual(
            location.notification_auth_token_hash,
            hash_location_notification_auth_token(new_notification_auth_token)
        )

    def test_ensure_client_config_notification_auth_token_changed_during_check(self):
        location = force_location()
        client, _ = self._get_client_config_client(location, notificationAuthToken=get_random_string(12))
        other_hash = hash_location_notification_auth_token(get_random_string(12))
        set_notification_auth_token = location.set_notification_auth_token

        def concurrent_set_notification_auth_token():
            Location.objects.filter(pk=location.pk).update(notification_auth_token_hash=other_hash)
            return set_notification_auth_token()

        location.set_notification_auth_token = concurrent_set_notification_auth_token
        with self.assertLogs("zentral.contrib.mdm.apps_books", "WARNING") as cm:
            self.assertFalse(ensure_client_config(location, client))
        self.assertEqual(cm.output, [f"WARNING:zentral.contrib.mdm.apps_books:Location {location.name}: "
                                     "notification token changed during the check"])
        client.update_client_config.assert_not_called()
        self.assertEqual(location.notification_auth_token_hash, other_hash)
        location.refresh_from_db()
        self.assertEqual(location.notification_auth_token_hash, other_hash)

    def test_ensure_client_config_not_configured(self):
        location = force_location()
        client, notification_auth_token = self._get_client_config_client(
            location, mdmInfo=None, notificationAuthToken=None, notificationUrl=None, subscribedNotificationTypes=None
        )
        self.assertTrue(ensure_client_config(location, client))
        client.update_client_config.assert_called_once()
        new_notification_auth_token = client.update_client_config.call_args.args[0]
        self.assertNotEqual(new_notification_auth_token, notification_auth_token)
        location.refresh_from_db()
        self.assertEqual(
            location.notification_auth_token_hash,
            hash_location_notification_auth_token(new_notification_auth_token)
        )

    # LocationAsset

    def test_location_asset_unlimited_no_availability_incident(self):
        location_asset = force_location_asset()
        location_asset.total_count = LocationAsset.UNLIMITED_COUNT
        location_asset.available_count = 0
        self.assertTrue(location_asset.is_unlimited())
        self.assertEqual(location_asset.get_availability_incident_severity(), Severity.NONE)

    def test_location_asset_limited_availability_incident(self):
        location_asset = force_location_asset()
        location_asset.total_count = LocationAsset.UNLIMITED_COUNT - 1
        location_asset.available_count = 0
        self.assertFalse(location_asset.is_unlimited())
        self.assertEqual(location_asset.get_availability_incident_severity(), Severity.MAJOR)

    # sync_unlimited_assets

    def test_sync_unlimited_assets(self):
        location = force_location()
        client = Mock()
        client.get_adam_id_assets.side_effect = [
            [{"adamId": "408709785",
              "assignedCount": 1,
              "availableCount": LocationAsset.UNLIMITED_COUNT - 1,
              "deviceAssignable": True,
              "pricingParam": "STDQ",
              "productType": "App",
              "retiredCount": 0,
              "revocable": True,
              "supportedPlatforms": ["iOS"],
              "totalCount": LocationAsset.UNLIMITED_COUNT}],
            [],
        ]
        client.get_asset_metadata.return_value = {"name": get_random_string(12), "bundleId": "pro.zentral.tests"}
        client.iter_asset_device_assignments.return_value = []
        notification_id = str(uuid.uuid4())
        with self.assertNoLogs("zentral.contrib.mdm.apps_books", "INFO"):
            events = list(sync_unlimited_assets(location, client, ["408709785", "377298193"], notification_id))
        self.assertEqual(client.get_adam_id_assets.call_args_list, [call("408709785"), call("377298193")])
        self.assertEqual(len(events), 2)
        self.assertIsInstance(events[0], AssetCreatedEvent)
        self.assertIsInstance(events[1], LocationAssetCreatedEvent)
        self.assertEqual(events[1].payload["notification_id"], notification_id)
        self.assertEqual(
            events[1].metadata.incident_updates[0].severity,
            Severity.NONE
        )
        location_asset = LocationAsset.objects.get(location=location, asset__adam_id="408709785")
        self.assertTrue(location_asset.is_unlimited())

    def test_sync_unlimited_assets_removed(self):
        location = force_location()
        removed_location_asset = force_location_asset(location=location)
        adam_id = removed_location_asset.asset.adam_id
        kept_location_asset = force_location_asset(
            asset=Asset.objects.create(adam_id=adam_id, pricing_param="STDQ", product_type=Asset.ProductType.APP,
                                       device_assignable=True, revocable=True, supported_platforms=["iOS"]),
            location=location
        )
        for location_asset in (removed_location_asset, kept_location_asset):
            location_asset.assigned_count = 1
            location_asset.available_count = location_asset.total_count = LocationAsset.UNLIMITED_COUNT
            location_asset.save()
        serial_number = get_random_string(12)
        DeviceAssignment.objects.create(location_asset=removed_location_asset, serial_number=serial_number)
        # no change for the other location
        other_location_asset = force_location_asset(asset=removed_location_asset.asset)
        other_location_asset.total_count = LocationAsset.UNLIMITED_COUNT
        other_location_asset.save()
        client = Mock()
        client.get_adam_id_assets.return_value = [
            {"adamId": adam_id,
             "assignedCount": 1,
             "availableCount": LocationAsset.UNLIMITED_COUNT,
             "deviceAssignable": True,
             "pricingParam": "STDQ",
             "productType": "App",
             "retiredCount": 0,
             "revocable": True,
             "supportedPlatforms": ["iOS"],
             "totalCount": LocationAsset.UNLIMITED_COUNT}
        ]
        client.get_asset_metadata.return_value = None
        client.iter_asset_device_assignments.return_value = []
        notification_id = str(uuid.uuid4())
        with self.assertLogs("zentral.contrib.mdm.apps_books", "INFO") as cm:
            events = list(sync_unlimited_assets(location, client, [adam_id], notification_id))
        self.assertEqual(cm.output, [f"INFO:zentral.contrib.mdm.apps_books:Location {location.name}: "
                                     f"asset {adam_id}/{removed_location_asset.asset.pricing_param} removed"])
        self.assertEqual(len(events), 2)
        self.assertIsInstance(events[0], LocationAssetUpdatedEvent)
        self.assertEqual(events[0].payload["notification_id"], notification_id)
        self.assertEqual(events[0].payload["total_count"], 0)
        self.assertEqual(events[0].metadata.incident_updates, [])
        self.assertIsInstance(events[1], DeviceAssignmentDeletedEvent)
        self.assertEqual(events[1].metadata.machine_serial_number, serial_number)
        removed_location_asset.refresh_from_db()
        for attr in LocationAsset.count_attrs:
            self.assertEqual(getattr(removed_location_asset, attr), 0)
        self.assertEqual(removed_location_asset.deviceassignment_set.count(), 0)
        kept_location_asset.refresh_from_db()
        self.assertTrue(kept_location_asset.is_unlimited())
        other_location_asset.refresh_from_db()
        self.assertTrue(other_location_asset.is_unlimited())
        # nothing left to do, nothing logged
        with self.assertNoLogs("zentral.contrib.mdm.apps_books", "INFO"):
            self.assertEqual(list(sync_unlimited_assets(location, client, [adam_id], notification_id)), [])

    # iter_location_assets_to_refresh

    def test_iter_location_assets_to_refresh_only_without_metadata(self):
        location = force_location()
        asset_with_metadata = force_asset()
        asset_with_metadata.name = get_random_string(12)
        asset_with_metadata.save()
        force_location_asset(asset=asset_with_metadata, location=location)
        asset_without_metadata = force_location_asset(location=location).asset
        asset_with_empty_name = force_asset()
        asset_with_empty_name.name = ""
        asset_with_empty_name.save()
        force_location_asset(asset=asset_with_empty_name, location=location)
        self.assertEqual(
            set(iter_location_assets_to_refresh(location)),
            {asset_without_metadata, asset_with_empty_name}
        )

    def test_iter_location_assets_to_refresh_all(self):
        location = force_location()
        asset = force_asset()
        asset.name = get_random_string(12)
        asset.save()
        force_location_asset(asset=asset, location=location)
        other_asset = force_location_asset(location=location).asset
        self.assertEqual(
            set(iter_location_assets_to_refresh(location, only_without_metadata=False)),
            {asset, other_asset}
        )

    def test_iter_location_assets_to_refresh_other_location(self):
        location = force_location()
        force_location_asset()
        self.assertEqual(list(iter_location_assets_to_refresh(location)), [])

    # refresh_asset_metadata

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_refresh_asset_metadata(self, post_event):
        asset = force_asset()
        asset_name = get_random_string(12)
        bundle_id = "pro.zentral.tests"
        client = Mock()
        client.get_asset_metadata.return_value = {"name": asset_name, "bundleId": bundle_id}
        self.assertTrue(refresh_asset_metadata(client, asset))
        client.get_asset_metadata.assert_called_once_with(asset.adam_id)
        asset.refresh_from_db()
        self.assertEqual(asset.name, asset_name)
        self.assertEqual(asset.bundle_id, bundle_id)
        self.assertEqual(asset.metadata, {"name": asset_name, "bundleId": bundle_id})
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AssetUpdatedEvent)
        self.assertEqual(event.payload["asset"]["name"], asset_name)
        self.assertEqual(
            event.get_linked_objects_keys(),
            {"mdm_asset": [(asset.adam_id, asset.pricing_param)]}
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_refresh_asset_metadata_not_in_storefront(self, post_event):
        asset = force_asset()
        client = Mock()
        client.get_asset_metadata.return_value = None
        self.assertFalse(refresh_asset_metadata(client, asset))
        asset.refresh_from_db()
        self.assertIsNone(asset.name)
        post_event.assert_not_called()

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_refresh_asset_metadata_noop(self, post_event):
        asset = force_asset()
        metadata = {"name": get_random_string(12), "bundleId": "pro.zentral.tests"}
        asset.metadata = metadata
        asset.name = metadata["name"]
        asset.bundle_id = metadata["bundleId"]
        asset.save()
        client = Mock()
        client.get_asset_metadata.return_value = metadata
        self.assertFalse(refresh_asset_metadata(client, asset))
        post_event.assert_not_called()

    # _update_location_asset_counts

    def test_update_location_asset_counts_noop(self):
        asset = force_asset()
        location = force_location()
        location_asset = LocationAsset.objects.create(
            location=location,
            asset=asset,
            assigned_count=3,
            available_count=7,
            retired_count=0,
            total_count=10
        )
        notification_id = str(uuid.uuid4())
        events = list(_update_location_asset_counts(location_asset, {"available_count": 0}, notification_id))
        self.assertEqual(len(events), 0)

    def test_update_location_asset_negative_counts_value_error(self):
        asset = force_asset()
        location = force_location()
        location_asset = LocationAsset.objects.create(
            location=location,
            asset=asset,
            assigned_count=0,
            available_count=0,
            retired_count=0,
            total_count=0
        )
        notification_id = str(uuid.uuid4())
        with self.assertRaises(ValueError):
            list(
                _update_location_asset_counts(
                    location_asset,
                    {"available_count": -1,
                     "total_count": -1},
                    notification_id)
            )

    def test_update_location_asset_assign_count_value_error(self):
        asset = force_asset()
        location = force_location()
        location_asset = LocationAsset.objects.create(
            location=location,
            asset=asset,
            assigned_count=0,
            available_count=0,
            retired_count=0,
            total_count=0
        )
        notification_id = str(uuid.uuid4())
        with self.assertRaises(ValueError):
            list(
                _update_location_asset_counts(
                    location_asset,
                    {"assigned_count": 1},
                    notification_id)
            )

    def test_update_location_asset_available_count_value_error(self):
        asset = force_asset()
        location = force_location()
        location_asset = LocationAsset.objects.create(
            location=location,
            asset=asset,
            assigned_count=0,
            available_count=0,
            retired_count=0,
            total_count=0
        )
        notification_id = str(uuid.uuid4())
        with self.assertRaises(ValueError):
            list(
                _update_location_asset_counts(
                    location_asset,
                    {"available_count": 1},
                    notification_id)
            )

    def test_update_location_asset_counts(self):
        asset = force_asset()
        location = force_location()
        location_asset = LocationAsset.objects.create(
            location=location,
            asset=asset,
            assigned_count=10,
            available_count=0,
            retired_count=0,
            total_count=10
        )
        notification_id = str(uuid.uuid4())
        events = list(
            _update_location_asset_counts(
                location_asset,
                {"total_count": 1,
                 "available_count": 1},
                notification_id
            )
        )
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, LocationAssetUpdatedEvent)
        self.assertEqual(
            event.payload,
            {'asset': {'pk': asset.pk, 'adam_id': asset.adam_id, 'pricing_param': asset.pricing_param},
             'location': {'pk': location.pk, 'mdm_info_id': str(location.mdm_info_id)},
             'assigned_count': 10,
             'available_count': 1,
             'retired_count': 0,
             'total_count': 11,
             'notification_id': notification_id}
        )
        location_asset.refresh_from_db()
        self.assertEqual(location_asset.available_count, 1)
        self.assertEqual(location_asset.total_count, 11)

    # update_location_asset_counts

    def test_update_location_asset_counts_ok(self):
        asset = force_asset()
        location = force_location()
        location_asset = LocationAsset.objects.create(
            location=location,
            asset=asset,
            assigned_count=10,
            available_count=0,
            retired_count=0,
            total_count=10
        )
        client = Mock()
        notification_id = str(uuid.uuid4())
        events = list(
            update_location_asset_counts(
                location, client,
                asset.adam_id, asset.pricing_param,
                {"total_count": 1,
                 "available_count": 1},
                notification_id
            )
        )
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, LocationAssetUpdatedEvent)
        location_asset.refresh_from_db()
        self.assertEqual(location_asset.available_count, 1)
        self.assertEqual(location_asset.total_count, 11)

    @patch("zentral.contrib.mdm.apps_books.sync_asset")
    def test_update_location_asset_counts_unknown_sync_required(self, sync_asset):
        location = force_location()
        client = Mock()
        sync_asset.return_value = []
        notification_id = str(uuid.uuid4())
        events = list(
            update_location_asset_counts(
                location, client,
                "00000000", "STDQ",
                {"total_count": 1,
                 "available_count": 1},
                notification_id,
            )
        )
        self.assertEqual(events, [])
        sync_asset.assert_called_once_with(location, client, "00000000", "STDQ", notification_id)

    def test_update_location_asset_counts_sync_required(self):
        asset = force_asset()
        location = force_location()
        location_asset = LocationAsset.objects.create(
            location=location,
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
            update_location_asset_counts(
                location, client,
                asset.adam_id, asset.pricing_param,
                {"total_count": -1,
                 "available_count": -1},
                notification_id
            )
        )
        self.assertEqual(len(events), 3)
        event = events[1]
        self.assertIsInstance(event, LocationAssetUpdatedEvent)
        location_asset.refresh_from_db()
        self.assertEqual(location_asset.available_count, 0)
        self.assertEqual(location_asset.total_count, 9)
        client.get_asset.assert_called_once_with(asset.adam_id, asset.pricing_param)

    # bulk_assign_location_asset

    @patch("zentral.contrib.mdm.apps_books.AppsBooksClient.make_request")
    def test_bulk_assign_location_asset(self, make_request):
        location_asset = force_location_asset()
        make_request.side_effect = [
            {"limits": {"maxAssets": 25, "maxSerialNumbers": 1}},
            {"eventId": "123"},
            {"eventId": "456"}
        ]
        dep_device1 = force_dep_device()
        dep_device2 = force_dep_device()
        self.assertEqual(
            bulk_assign_location_asset(location_asset, [dep_device1.virtual_server, dep_device2.virtual_server]),
            2
        )
        self.assertEqual(len(make_request.call_args_list), 3)
        self.assertIn(
            call("service/config"),
            make_request.call_args_list
        )
        self.assertIn(
            call("service/config"),
            make_request.call_args_list
        )
        assets = [{'adamId': location_asset.asset.adam_id, 'pricingParam': location_asset.asset.pricing_param}]
        self.assertIn(
            call("assets/associate", json={'assets': assets, 'serialNumbers': [dep_device1.serial_number]}),
            make_request.call_args_list
        )
        self.assertIn(
            call("assets/associate", json={'assets': assets, 'serialNumbers': [dep_device2.serial_number]}),
            make_request.call_args_list
        )

    @patch("zentral.contrib.mdm.apps_books.AppsBooksClient.make_request")
    def test_bulk_assign_location_asset_each_device_once(self, make_request):
        location_asset = force_location_asset()
        make_request.side_effect = [
            {"limits": {"maxAssets": 25, "maxSerialNumbers": 1000}},
            {"eventId": "123"},
        ]
        dep_device1 = force_dep_device()
        dep_device2 = force_dep_device()
        # the same device in the second virtual server
        dep_device3 = force_dep_device(server=dep_device2.virtual_server)
        DEPDevice.objects.filter(pk=dep_device3.pk).update(serial_number=dep_device1.serial_number)
        # a device removed from the first virtual server
        force_dep_device(server=dep_device1.virtual_server, op_type=DEPDevice.OP_TYPE_DELETED)
        self.assertEqual(
            bulk_assign_location_asset(location_asset, [dep_device1.virtual_server, dep_device2.virtual_server]),
            2
        )
        self.assertEqual(len(make_request.call_args_list), 2)
        args, kwargs = make_request.call_args_list[1]
        self.assertEqual(args, ("assets/associate",))
        self.assertEqual(
            kwargs["json"]["assets"],
            [{'adamId': location_asset.asset.adam_id, 'pricingParam': location_asset.asset.pricing_param}]
        )
        self.assertEqual(
            sorted(kwargs["json"]["serialNumbers"]),
            sorted([dep_device1.serial_number, dep_device2.serial_number])
        )

    # ensure_target_asset_assignments

    @patch("zentral.contrib.mdm.apps_books.AppsBooksClient.make_request")
    def test_ensure_target_asset_assignments_max_assets(self, make_request):
        location = force_location()
        event_id1 = str(uuid.uuid4())
        event_id2 = str(uuid.uuid4())
        make_request.side_effect = [
            {"limits": {"maxAssets": 2, "maxSerialNumbers": 1000}},
            {"eventId": event_id1},
            {"eventId": event_id2},
        ]
        target = Mock(
            serial_number=get_random_string(10),
            missing_asset_assignments=[(str(location.mdm_info_id), adam_id, "STDQ")
                                       for adam_id in ("un", "deux", "trois")],
        )
        ensure_target_asset_assignments(target)
        self.assertEqual(
            make_request.call_args_list,
            [call("service/config"),
             call("assets/associate", json={"assets": [{"adamId": "un", "pricingParam": "STDQ"},
                                                       {"adamId": "deux", "pricingParam": "STDQ"}],
                                            "serialNumbers": [target.serial_number]}),
             call("assets/associate", json={"assets": [{"adamId": "trois", "pricingParam": "STDQ"}],
                                            "serialNumbers": [target.serial_number]})]
        )
        self.assertEqual(cache.get(get_otf_association_cache_key(event_id1)), "1")
        self.assertEqual(cache.get(get_otf_association_cache_key(event_id2)), "1")

    @patch("zentral.contrib.mdm.apps_books.AppsBooksClient.make_request")
    def test_ensure_target_asset_assignments_second_request_error(self, make_request):
        location = force_location()
        event_id = str(uuid.uuid4())
        make_request.side_effect = [
            {"limits": {"maxAssets": 1, "maxSerialNumbers": 1000}},
            {"eventId": event_id},
            AppsBooksAPIError("Error 9646"),
        ]
        target = Mock(
            serial_number=get_random_string(10),
            missing_asset_assignments=[(str(location.mdm_info_id), adam_id, "STDQ")
                                       for adam_id in ("un", "deux")],
        )
        with self.assertLogs("zentral.contrib.mdm.apps_books", level="ERROR") as cm:
            ensure_target_asset_assignments(target)
        self.assertEqual(len(make_request.call_args_list), 3)
        # the device is still notified when the association of the first request is done
        self.assertEqual(cache.get(get_otf_association_cache_key(event_id)), "1")
        self.assertEqual(len(cm.output), 1)
        self.assertIn(f"Could not post device {target.serial_number} associations", cm.output[0])

    def test_ensure_target_asset_assignments_new_server_token(self):
        location = force_location()
        _, client = location_cache.get(location.mdm_info_id)
        # the location form saves the new token in another process
        other_location = Location.objects.get(pk=location.pk)
        other_location.server_token_hash = get_random_string(40, allowed_chars="abcdef0123456789")
        new_server_token = get_random_string(12)
        other_location.set_server_token(new_server_token)
        other_location.save()
        event_id = str(uuid.uuid4())
        target = Mock(
            serial_number=get_random_string(10),
            missing_asset_assignments=[(str(location.mdm_info_id), "un", "STDQ")],
        )
        with patch.object(client, "session") as session:
            session.headers = {}
            session.get.return_value = Mock(
                status_code=200, **{"json.return_value": {"limits": {"maxAssets": 25, "maxSerialNumbers": 1000}}}
            )
            session.post.side_effect = [
                Mock(status_code=401, **{"json.return_value": {"errorNumber": 9625}}),
                Mock(status_code=200, **{"json.return_value": {"eventId": event_id}}),
            ]
            ensure_target_asset_assignments(target)
        self.assertEqual(session.headers["Authorization"], f"Bearer {new_server_token}")
        self.assertEqual(len(session.post.call_args_list), 2)
        self.assertEqual(cache.get(get_otf_association_cache_key(event_id)), "1")

    # associate_location_asset

    def test_associate_location_asset(self):
        asset = force_asset()
        location = force_location()
        location_asset = LocationAsset.objects.create(
            location=location,
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
            associate_location_asset(
                location, client,
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
                location_asset=location_asset,
                serial_number=serial_number
            ).count(),
            1
        )
        event = events[1]
        self.assertIsInstance(event, LocationAssetUpdatedEvent)
        location_asset.refresh_from_db()
        self.assertEqual(location_asset.assigned_count, 11)
        self.assertEqual(location_asset.available_count, 0)

    def test_associate_location_asset_unknown_location_asset(self):
        location = force_location()
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
            associate_location_asset(
                location, client,
                "408709785", "STDQ",
                [serial_number],
                event_id, notification_id
            )
        )
        self.assertEqual(len(events), 3)
        self.assertEqual(Asset.objects.filter(adam_id="408709785", pricing_param="STDQ").count(), 1)
        location_asset = LocationAsset.objects.get(
            asset__adam_id="408709785",
            asset__pricing_param="STDQ",
            location=location
        )
        self.assertEqual(location_asset.assigned_count, 9)
        self.assertEqual(location_asset.total_count, 9)
        self.assertEqual(
            DeviceAssignment.objects.filter(
                location_asset=location_asset,
                serial_number=serial_number
            ).count(),
            1
        )

    def test_associate_location_asset_bad_counts(self):
        asset = force_asset()
        location = force_location()
        LocationAsset.objects.create(
            location=location,
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
            associate_location_asset(
                location, client,
                asset.adam_id, asset.pricing_param,
                [serial_number],
                event_id, notification_id
            )
        )
        self.assertEqual(len(events), 3)
        self.assertIsInstance(events[0], DeviceAssignmentCreatedEvent)
        self.assertIsInstance(events[1], AssetUpdatedEvent)
        self.assertIsInstance(events[2], LocationAssetUpdatedEvent)

    # disassociate_location_asset

    def test_disassociate_location_asset(self):
        asset = force_asset()
        location = force_location()
        location_asset = LocationAsset.objects.create(
            location=location,
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
        DeviceAssignment.objects.create(location_asset=location_asset, serial_number=serial_number)
        events = list(
            disassociate_location_asset(
                location, client,
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
                location_asset=location_asset,
                serial_number=serial_number
            ).count(),
            0
        )
        event = events[1]
        self.assertIsInstance(event, LocationAssetUpdatedEvent)
        location_asset.refresh_from_db()
        self.assertEqual(location_asset.assigned_count, 9)
        self.assertEqual(location_asset.available_count, 2)

    def test_disassociate_location_unknown_asset(self):
        location = force_location()
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
            disassociate_location_asset(
                location, client,
                "408709785", "STDQ",
                [serial_number],
                event_id, notification_id
            )
        )
        self.assertEqual(len(events), 2)
        self.assertIsInstance(events[0], AssetCreatedEvent)
        self.assertIsInstance(events[1], LocationAssetCreatedEvent)
        self.assertEqual(Asset.objects.filter(adam_id="408709785", pricing_param="STDQ").count(), 1)
        location_asset = LocationAsset.objects.get(
            asset__adam_id="408709785",
            asset__pricing_param="STDQ",
            location=location
        )
        self.assertEqual(location_asset.assigned_count, 9)
        self.assertEqual(location_asset.total_count, 9)
        self.assertEqual(
            DeviceAssignment.objects.filter(
                location_asset=location_asset,
                serial_number=serial_number
            ).count(),
            0
        )

    def test_disassociate_location_bad_counts(self):
        asset = force_asset()
        location = force_location()
        location_asset = LocationAsset.objects.create(
            location=location,
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
        DeviceAssignment.objects.create(location_asset=location_asset, serial_number=serial_number)
        client.iter_asset_device_assignments.return_value = []
        event_id = str(uuid.uuid4())
        notification_id = str(uuid.uuid4())
        events = list(
            disassociate_location_asset(
                location, client,
                asset.adam_id, asset.pricing_param,
                [serial_number],
                event_id, notification_id
            )
        )
        self.assertEqual(len(events), 2)
        self.assertIsInstance(events[0], DeviceAssignmentDeletedEvent)
        self.assertIsInstance(events[1], AssetUpdatedEvent)

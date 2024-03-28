from unittest.mock import patch, Mock
import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.mdm.apps_books import (_sync_asset_d,
                                            _update_assignments,
                                            _update_or_create_asset,
                                            _update_or_create_location_asset,
                                            _update_location_asset_counts,
                                            associate_location_asset,
                                            disassociate_location_asset,
                                            sync_asset, sync_assets,
                                            update_location_asset_counts)
from zentral.contrib.mdm.events import (AssetCreatedEvent, AssetUpdatedEvent,
                                        DeviceAssignmentCreatedEvent, DeviceAssignmentDeletedEvent,
                                        LocationAssetCreatedEvent, LocationAssetUpdatedEvent)
from zentral.contrib.mdm.models import Asset, DeviceAssignment, LocationAsset
from zentral.core.incidents.models import Severity
from .utils import force_asset, force_location


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
        self.assertEqual(event.payload["pk"], asset.pk)
        self.assertEqual(event.payload["adam_id"], "yolo")
        self.assertEqual(event.payload["pricing_param"], "fomo")
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
        self.assertEqual(event.payload["pk"], asset.pk)
        self.assertEqual(event.payload["adam_id"], asset.adam_id)
        self.assertEqual(event.payload["pricing_param"], asset.pricing_param)
        self.assertEqual(event.payload["supported_platforms"], ["iOS"])
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
             "location": {"pk": location.pk, "mdm_info_id": location.mdm_info_id},
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
             "location": {"pk": location.pk, "mdm_info_id": location.mdm_info_id},
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
             "location": {"pk": location.pk, "mdm_info_id": location.mdm_info_id},
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
             'location': {'pk': location.pk, 'mdm_info_id': location.mdm_info_id},
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
             'location': {'pk': location.pk, 'mdm_info_id': location.mdm_info_id},
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
        client = Mock()
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
             'location': {'pk': location.pk, 'mdm_info_id': location.mdm_info_id},
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

    # associate_location_asset

    @patch("zentral.contrib.mdm.apps_books.queue_install_application_command_if_necessary")
    def test_associate_location_asset(self, queue_install_application_command_if_necessary):
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
        queue_install_application_command_if_necessary.assert_called_once_with(
            location, serial_number, asset.adam_id, asset.pricing_param
        )

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

    @patch("zentral.contrib.mdm.apps_books.clear_on_the_fly_assignment")
    def test_disassociate_location_asset(self, clear_on_the_fly_assignment):
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
        clear_on_the_fly_assignment.assert_called_once_with(
            location, serial_number, asset.adam_id, asset.pricing_param, "disassociate success"
        )

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

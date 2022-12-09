import datetime
import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.mdm.apps_books import _update_or_create_asset, _update_or_create_server_token_asset
from zentral.contrib.mdm.events import (AssetCreatedEvent, AssetUpdatedEvent,
                                        ServerTokenAssetCreatedEvent)
from zentral.contrib.mdm.models import Asset, ServerToken, ServerTokenAsset
from zentral.core.incidents.models import Severity


class MDMAppsBooksAssetsAssignmentsSyncTestCase(TestCase):

    # tools

    def _force_asset(self):
        return Asset.objects.create(
            adam_id=get_random_string(12),
            pricing_param=get_random_string(12),
            product_type=Asset.ProductType.APP,
            device_assignable=True,
            revocable=False,
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
                {"assigned_count": 0,
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
             "assigned_count": 0,
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
                {"assigned_count": 0,
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
             "assigned_count": 0,
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

import datetime
from unittest.mock import patch, Mock
import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.apps_books import (ensure_enrolled_device_asset_association,
                                            queue_install_application_command_if_necessary,
                                            clear_on_the_fly_assignment)
from zentral.contrib.mdm.commands.base import load_command
from zentral.contrib.mdm.commands.install_application import InstallApplication
from zentral.contrib.mdm.models import (Artifact, ArtifactType, ArtifactVersion,
                                        Asset, Blueprint, BlueprintArtifact, DeviceAssignment, DeviceCommand,
                                        EnrolledDeviceAssetAssociation,
                                        ServerToken, ServerTokenAsset,
                                        StoreApp)
from .utils import force_dep_enrollment_session


class MDMOnTheFlyAssignmentTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.dep_enrollment_session, _, _ = force_dep_enrollment_session(
            cls.mbu,
            authenticated=True,
            completed=True,
            realm_user=True
        )
        cls.blueprint = Blueprint.objects.create(name=get_random_string(32))
        cls.enrolled_device = cls.dep_enrollment_session.enrolled_device
        cls.enrolled_device.server_token = cls.server_token = cls._force_server_token()
        cls.enrolled_device.blueprint = cls.blueprint
        cls.enrolled_device.save()

    # tools

    @staticmethod
    def _force_asset():
        return Asset.objects.create(
            adam_id=get_random_string(12, allowed_chars="0123456789"),
            pricing_param=get_random_string(12),
            product_type=Asset.ProductType.APP,
            device_assignable=True,
            revocable=True,
            supported_platforms=["iOS", "macOS"]
        )

    @staticmethod
    def _force_server_token():
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

    # ensure_enrolled_device_asset_association

    def test_ensure_enrolled_device_asset_association_no_server_token(self):
        asset = self._force_asset()
        self.enrolled_device.server_token = None
        self.assertIsNone(self.enrolled_device.server_token)
        self.assertFalse(ensure_enrolled_device_asset_association(self.enrolled_device, asset))

    def test_ensure_enrolled_device_asset_association_noop(self):
        asset = self._force_asset()
        server_token_asset = ServerTokenAsset.objects.create(server_token=self.server_token, asset=asset)
        DeviceAssignment.objects.create(
            serial_number=self.enrolled_device.serial_number,
            server_token_asset=server_token_asset
        )
        self.assertTrue(ensure_enrolled_device_asset_association(self.enrolled_device, asset))

    @patch("zentral.contrib.mdm.apps_books.server_token_cache.get")
    def test_ensure_enrolled_device_asset_association_created_ok(self, server_token_cache_get):
        client = Mock()
        client.post_device_association.return_value = {"eventId": str(uuid.uuid4())}
        server_token_cache_get.return_value = (None, client)
        asset = self._force_asset()
        self.assertFalse(ensure_enrolled_device_asset_association(self.enrolled_device, asset))
        server_token_cache_get.assert_called_once_with(self.server_token.mdm_info_id)
        client.post_device_association.assert_called_once_with(self.enrolled_device.serial_number, asset)
        edaa = EnrolledDeviceAssetAssociation.objects.get(enrolled_device=self.enrolled_device, asset=asset)
        self.assertEqual(edaa.attempts, 1)
        self.assertIsNotNone(edaa.last_attempted_at)

    @patch("zentral.contrib.mdm.apps_books.server_token_cache.get")
    def test_ensure_enrolled_device_asset_association_created_no_event_id(self, server_token_cache_get):
        client = Mock()
        client.post_device_association.return_value = {}
        server_token_cache_get.return_value = (None, client)
        asset = self._force_asset()
        self.assertFalse(ensure_enrolled_device_asset_association(self.enrolled_device, asset))
        server_token_cache_get.assert_called_once_with(self.server_token.mdm_info_id)
        client.post_device_association.assert_called_once_with(self.enrolled_device.serial_number, asset)
        qs = EnrolledDeviceAssetAssociation.objects.filter(enrolled_device=self.enrolled_device, asset=asset)
        self.assertEqual(qs.count(), 0)

    @patch("zentral.contrib.mdm.apps_books.server_token_cache.get")
    def test_ensure_enrolled_device_asset_association_created_client_error(self, server_token_cache_get):
        client = Mock()
        client.post_device_association.side_effect = KeyError("foo")
        server_token_cache_get.return_value = (None, client)
        asset = self._force_asset()
        self.assertFalse(ensure_enrolled_device_asset_association(self.enrolled_device, asset))
        server_token_cache_get.assert_called_once_with(self.server_token.mdm_info_id)
        client.post_device_association.assert_called_once_with(self.enrolled_device.serial_number, asset)
        qs = EnrolledDeviceAssetAssociation.objects.filter(enrolled_device=self.enrolled_device, asset=asset)
        self.assertEqual(qs.count(), 0)

    @patch("zentral.contrib.mdm.apps_books.server_token_cache.get")
    def test_ensure_enrolled_device_asset_association_existing_fresh_attempt_noop(self, server_token_cache_get):
        asset = self._force_asset()
        edaa = EnrolledDeviceAssetAssociation.objects.create(
            enrolled_device=self.enrolled_device,
            asset=asset,
        )
        edaa.attempts = 1
        last_attempted_at = datetime.datetime.utcnow()  # too recent, noop
        edaa.last_attempted_at = last_attempted_at
        edaa.save()
        self.assertFalse(ensure_enrolled_device_asset_association(self.enrolled_device, asset))
        edaa.refresh_from_db()
        self.assertEqual(edaa.attempts, 1)
        self.assertEqual(edaa.last_attempted_at, last_attempted_at)
        server_token_cache_get.assert_not_called()

    @patch("zentral.contrib.mdm.apps_books.server_token_cache.get")
    def test_ensure_enrolled_device_asset_association_created_old_attempt_ok(self, server_token_cache_get):
        client = Mock()
        client.post_device_association.return_value = {"eventId": str(uuid.uuid4())}
        server_token_cache_get.return_value = (None, client)
        asset = self._force_asset()
        edaa = EnrolledDeviceAssetAssociation.objects.create(
            enrolled_device=self.enrolled_device,
            asset=asset,
        )
        edaa.attempts = 1
        last_attempted_at = datetime.datetime.utcnow() - datetime.timedelta(days=1)  # too old, new attempt
        edaa.last_attempted_at = last_attempted_at
        edaa.save()
        self.assertFalse(ensure_enrolled_device_asset_association(self.enrolled_device, asset))
        server_token_cache_get.assert_called_once_with(self.server_token.mdm_info_id)
        client.post_device_association.assert_called_once_with(self.enrolled_device.serial_number, asset)
        edaa = EnrolledDeviceAssetAssociation.objects.get(enrolled_device=self.enrolled_device, asset=asset)
        self.assertEqual(edaa.attempts, 2)
        self.assertTrue(edaa.last_attempted_at > last_attempted_at)

    # queue_install_application_command_if_necessary

    def test_queue_install_application_command_if_necessary_noop(self):
        asset = self._force_asset()
        queue_install_application_command_if_necessary(
            self.enrolled_device.server_token,
            self.enrolled_device.serial_number,
            asset.adam_id,
            asset.pricing_param
        )
        self.assertEqual(DeviceCommand.objects.filter(enrolled_device=self.enrolled_device).count(), 0)

    def test_queue_install_application_command_if_necessary_no_next_to_install(self):
        asset = self._force_asset()
        edaa = EnrolledDeviceAssetAssociation.objects.create(
            enrolled_device=self.enrolled_device,
            asset=asset,
        )
        edaa.attempts = 1
        last_attempted_at = datetime.datetime.utcnow() - datetime.timedelta(seconds=10)
        edaa.last_attempted_at = last_attempted_at
        edaa.save()
        queue_install_application_command_if_necessary(
            self.enrolled_device.server_token,
            self.enrolled_device.serial_number,
            asset.adam_id,
            asset.pricing_param
        )
        self.assertEqual(DeviceCommand.objects.filter(enrolled_device=self.enrolled_device).count(), 0)
        self.assertEqual(
            EnrolledDeviceAssetAssociation.objects.filter(
                enrolled_device=self.enrolled_device,
                asset=asset
            ).count(), 0
        )

    def test_queue_install_application_command_if_necessary_install(self):
        asset = self._force_asset()
        edaa = EnrolledDeviceAssetAssociation.objects.create(
            enrolled_device=self.enrolled_device,
            asset=asset,
        )
        edaa.attempts = 1
        last_attempted_at = datetime.datetime.utcnow() - datetime.timedelta(seconds=10)
        edaa.last_attempted_at = last_attempted_at
        edaa.save()
        artifact = Artifact.objects.create(
            name=get_random_string(32),
            type=ArtifactType.StoreApp.name,
            channel="Device",
            platforms=["macOS"],
        )
        artifact_version = ArtifactVersion.objects.create(
            artifact=artifact,
            version=1
        )
        StoreApp.objects.create(
            artifact_version=artifact_version,
            asset=asset,
        )
        BlueprintArtifact.objects.create(
            blueprint=self.enrolled_device.blueprint,
            install_before_setup_assistant=True,
            artifact=artifact
        )
        queue_install_application_command_if_necessary(
            self.enrolled_device.server_token,
            self.enrolled_device.serial_number,
            asset.adam_id,
            asset.pricing_param
        )
        cmd_qs = DeviceCommand.objects.filter(enrolled_device=self.enrolled_device)
        self.assertEqual(cmd_qs.count(), 1)
        db_cmd = cmd_qs.first()
        cmd = load_command(db_cmd)
        self.assertIsInstance(cmd, InstallApplication)
        self.assertEqual(
            EnrolledDeviceAssetAssociation.objects.filter(
                enrolled_device=self.enrolled_device,
                asset=asset
            ).count(), 0
        )
        cmd_payload = cmd.build_command()
        self.assertEqual(cmd_payload["iTunesStoreID"], int(asset.adam_id))

    # clear_on_the_fly_assignment

    def test_clear_on_the_fly_assignment(self):
        asset = self._force_asset()
        edaa = EnrolledDeviceAssetAssociation.objects.create(
            enrolled_device=self.enrolled_device,
            asset=asset,
        )
        edaa.attempts = 1
        last_attempted_at = datetime.datetime.utcnow() - datetime.timedelta(seconds=10)
        edaa.last_attempted_at = last_attempted_at
        edaa.save()
        clear_on_the_fly_assignment(
            self.enrolled_device.server_token,
            self.enrolled_device.serial_number,
            asset.adam_id,
            asset.pricing_param,
            "yolo"
        )
        qs = EnrolledDeviceAssetAssociation.objects.filter(enrolled_device=self.enrolled_device, asset=asset)
        self.assertEqual(qs.count(), 0)

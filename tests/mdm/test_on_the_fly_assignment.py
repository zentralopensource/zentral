import datetime
from unittest.mock import patch, Mock
import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.apps_books import (ensure_enrolled_device_location_asset_association,
                                            queue_install_application_command_if_necessary,
                                            clear_on_the_fly_assignment)
from zentral.contrib.mdm.commands.base import load_command
from zentral.contrib.mdm.commands.install_application import InstallApplication
from zentral.contrib.mdm.models import (Artifact, ArtifactType, ArtifactVersion,
                                        Asset, Blueprint, BlueprintArtifact, DeviceAssignment, DeviceCommand,
                                        EnrolledDeviceLocationAssetAssociation,
                                        Location, LocationAsset,
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
        cls.enrolled_device.blueprint = cls.blueprint
        cls.enrolled_device.save()

    # tools

    @staticmethod
    def _force_location_asset():
        asset = Asset.objects.create(
            adam_id=get_random_string(12, allowed_chars="0123456789"),
            pricing_param=get_random_string(12),
            product_type=Asset.ProductType.APP,
            device_assignable=True,
            revocable=True,
            supported_platforms=["iOS", "macOS"]
        )
        location = Location(
            server_token_hash=get_random_string(40, allowed_chars='abcdef0123456789'),
            server_token=get_random_string(12),
            server_token_expiration_date=datetime.date(2050, 1, 1),
            organization_name=get_random_string(12),
            country_code="DE",
            library_uid=str(uuid.uuid4()),
            name=get_random_string(12),
            platform="enterprisestore",
            website_url="https://business.apple.com",
            mdm_info_id=uuid.uuid4(),
        )
        location.set_notification_auth_token()
        location.save()
        return LocationAsset.objects.create(asset=asset, location=location)

    # ensure_enrolled_device_location_asset_association

    def test_ensure_enrolled_device_location_asset_association_noop(self):
        location_asset = self._force_location_asset()
        DeviceAssignment.objects.create(
            serial_number=self.enrolled_device.serial_number,
            location_asset=location_asset
        )
        self.assertTrue(ensure_enrolled_device_location_asset_association(self.enrolled_device, location_asset))

    @patch("zentral.contrib.mdm.apps_books.location_cache.get")
    def test_ensure_enrolled_device_location_asset_association_created_ok(self, location_cache_get):
        client = Mock()
        client.post_device_association.return_value = {"eventId": str(uuid.uuid4())}
        location_cache_get.return_value = (None, client)
        location_asset = self._force_location_asset()
        self.assertFalse(ensure_enrolled_device_location_asset_association(self.enrolled_device, location_asset))
        location_cache_get.assert_called_once_with(location_asset.location.mdm_info_id)
        client.post_device_association.assert_called_once_with(self.enrolled_device.serial_number,
                                                               location_asset.asset)
        edlaa = EnrolledDeviceLocationAssetAssociation.objects.get(enrolled_device=self.enrolled_device,
                                                                   location_asset=location_asset)
        self.assertEqual(edlaa.attempts, 1)
        self.assertIsNotNone(edlaa.last_attempted_at)

    @patch("zentral.contrib.mdm.apps_books.location_cache.get")
    def test_ensure_enrolled_device_location_asset_association_created_no_event_id(self, location_cache_get):
        client = Mock()
        client.post_device_association.return_value = {}
        location_cache_get.return_value = (None, client)
        location_asset = self._force_location_asset()
        self.assertFalse(ensure_enrolled_device_location_asset_association(self.enrolled_device, location_asset))
        location_cache_get.assert_called_once_with(location_asset.location.mdm_info_id)
        client.post_device_association.assert_called_once_with(self.enrolled_device.serial_number,
                                                               location_asset.asset)
        qs = EnrolledDeviceLocationAssetAssociation.objects.filter(enrolled_device=self.enrolled_device,
                                                                   location_asset=location_asset)
        self.assertEqual(qs.count(), 0)

    @patch("zentral.contrib.mdm.apps_books.location_cache.get")
    def test_ensure_enrolled_device_location_asset_association_created_client_error(self, location_cache_get):
        client = Mock()
        client.post_device_association.side_effect = KeyError("foo")
        location_cache_get.return_value = (None, client)
        location_asset = self._force_location_asset()
        self.assertFalse(ensure_enrolled_device_location_asset_association(self.enrolled_device, location_asset))
        location_cache_get.assert_called_once_with(location_asset.location.mdm_info_id)
        client.post_device_association.assert_called_once_with(self.enrolled_device.serial_number,
                                                               location_asset.asset)
        qs = EnrolledDeviceLocationAssetAssociation.objects.filter(enrolled_device=self.enrolled_device,
                                                                   location_asset=location_asset)
        self.assertEqual(qs.count(), 0)

    @patch("zentral.contrib.mdm.apps_books.location_cache.get")
    def test_ensure_enrolled_device_location_asset_association_existing_fresh_attempt_noop(self, location_cache_get):
        location_asset = self._force_location_asset()
        edlaa = EnrolledDeviceLocationAssetAssociation.objects.create(
            enrolled_device=self.enrolled_device,
            location_asset=location_asset,
        )
        edlaa.attempts = 1
        last_attempted_at = datetime.datetime.utcnow()  # too recent, noop
        edlaa.last_attempted_at = last_attempted_at
        edlaa.save()
        self.assertFalse(ensure_enrolled_device_location_asset_association(self.enrolled_device, location_asset))
        edlaa.refresh_from_db()
        self.assertEqual(edlaa.attempts, 1)
        self.assertEqual(edlaa.last_attempted_at, last_attempted_at)
        location_cache_get.assert_not_called()

    @patch("zentral.contrib.mdm.apps_books.location_cache.get")
    def test_ensure_enrolled_device_location_asset_association_created_old_attempt_ok(self, location_cache_get):
        client = Mock()
        client.post_device_association.return_value = {"eventId": str(uuid.uuid4())}
        location_cache_get.return_value = (None, client)
        location_asset = self._force_location_asset()
        edlaa = EnrolledDeviceLocationAssetAssociation.objects.create(
            enrolled_device=self.enrolled_device,
            location_asset=location_asset,
        )
        edlaa.attempts = 1
        last_attempted_at = datetime.datetime.utcnow() - datetime.timedelta(days=1)  # too old, new attempt
        edlaa.last_attempted_at = last_attempted_at
        edlaa.save()
        self.assertFalse(ensure_enrolled_device_location_asset_association(self.enrolled_device, location_asset))
        location_cache_get.assert_called_once_with(location_asset.location.mdm_info_id)
        client.post_device_association.assert_called_once_with(self.enrolled_device.serial_number,
                                                               location_asset.asset)
        edlaa = EnrolledDeviceLocationAssetAssociation.objects.get(enrolled_device=self.enrolled_device,
                                                                   location_asset=location_asset)
        self.assertEqual(edlaa.attempts, 2)
        self.assertTrue(edlaa.last_attempted_at > last_attempted_at)

    # queue_install_application_command_if_necessary

    def test_queue_install_application_command_if_necessary_noop(self):
        location_asset = self._force_location_asset()
        queue_install_application_command_if_necessary(
            location_asset.location,
            self.enrolled_device.serial_number,
            location_asset.asset.adam_id,
            location_asset.asset.pricing_param
        )
        self.assertEqual(DeviceCommand.objects.filter(enrolled_device=self.enrolled_device).count(), 0)

    def test_queue_install_application_command_if_necessary_no_next_to_install(self):
        location_asset = self._force_location_asset()
        edlaa = EnrolledDeviceLocationAssetAssociation.objects.create(
            enrolled_device=self.enrolled_device,
            location_asset=location_asset
        )
        edlaa.attempts = 1
        last_attempted_at = datetime.datetime.utcnow() - datetime.timedelta(seconds=10)
        edlaa.last_attempted_at = last_attempted_at
        edlaa.save()
        queue_install_application_command_if_necessary(
            location_asset.location,
            self.enrolled_device.serial_number,
            location_asset.asset.adam_id,
            location_asset.asset.pricing_param
        )
        self.assertEqual(DeviceCommand.objects.filter(enrolled_device=self.enrolled_device).count(), 0)
        self.assertEqual(
            EnrolledDeviceLocationAssetAssociation.objects.filter(
                enrolled_device=self.enrolled_device,
                location_asset=location_asset
            ).count(), 0
        )

    def test_queue_install_application_command_if_necessary_install(self):
        location_asset = self._force_location_asset()
        edlaa = EnrolledDeviceLocationAssetAssociation.objects.create(
            enrolled_device=self.enrolled_device,
            location_asset=location_asset
        )
        edlaa.attempts = 1
        last_attempted_at = datetime.datetime.utcnow() - datetime.timedelta(seconds=10)
        edlaa.last_attempted_at = last_attempted_at
        edlaa.save()
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
            location_asset=location_asset,
        )
        BlueprintArtifact.objects.create(
            blueprint=self.enrolled_device.blueprint,
            install_before_setup_assistant=True,
            artifact=artifact
        )
        queue_install_application_command_if_necessary(
            location_asset.location,
            self.enrolled_device.serial_number,
            location_asset.asset.adam_id,
            location_asset.asset.pricing_param
        )
        cmd_qs = DeviceCommand.objects.filter(enrolled_device=self.enrolled_device)
        self.assertEqual(cmd_qs.count(), 1)
        db_cmd = cmd_qs.first()
        cmd = load_command(db_cmd)
        self.assertIsInstance(cmd, InstallApplication)
        self.assertEqual(
            EnrolledDeviceLocationAssetAssociation.objects.filter(
                enrolled_device=self.enrolled_device,
                location_asset=location_asset
            ).count(), 0
        )
        cmd_payload = cmd.build_command()
        self.assertEqual(cmd_payload["iTunesStoreID"], int(location_asset.asset.adam_id))

    # clear_on_the_fly_assignment

    def test_clear_on_the_fly_assignment(self):
        location_asset = self._force_location_asset()
        edlaa = EnrolledDeviceLocationAssetAssociation.objects.create(
            enrolled_device=self.enrolled_device,
            location_asset=location_asset,
        )
        edlaa.attempts = 1
        last_attempted_at = datetime.datetime.utcnow() - datetime.timedelta(seconds=10)
        edlaa.last_attempted_at = last_attempted_at
        edlaa.save()
        clear_on_the_fly_assignment(
            location_asset.location,
            self.enrolled_device.serial_number,
            location_asset.asset.adam_id,
            location_asset.asset.pricing_param,
            "yolo"
        )
        qs = EnrolledDeviceLocationAssetAssociation.objects.filter(enrolled_device=self.enrolled_device,
                                                                   location_asset=location_asset)
        self.assertEqual(qs.count(), 0)

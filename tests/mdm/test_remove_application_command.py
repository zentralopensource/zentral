import datetime
import plistlib
import uuid
from unittest.mock import patch, Mock
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.artifacts import Target, update_blueprint_serialized_artifacts
from zentral.contrib.mdm.commands import RemoveApplication
from zentral.contrib.mdm.commands.scheduling import _remove_artifacts
from zentral.contrib.mdm.models import (
    Artifact,
    ArtifactVersion,
    Asset,
    Blueprint,
    BlueprintArtifact,
    Channel,
    DeviceArtifact,
    Location,
    LocationAsset,
    Platform,
    RequestStatus,
    StoreApp,
    TargetArtifact,
)
from .utils import force_dep_enrollment_session


class RemoveApplicationCommandTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.dep_enrollment_session, _, _ = force_dep_enrollment_session(
            cls.mbu, authenticated=True, completed=True, realm_user=True
        )
        cls.enrolled_device = cls.dep_enrollment_session.enrolled_device
        cls.blueprint = Blueprint.objects.create(name=get_random_string(12))
        cls.enrolled_device.blueprint = cls.blueprint
        cls.enrolled_device.save()

    def _force_store_app(
        self,
        artifact=None,
        bundle_id=None,
        version=None,
        status=None,
        in_blueprint=False,
    ):
        if artifact is None:
            artifact = Artifact.objects.create(
                name=get_random_string(32),
                type=Artifact.Type.STORE_APP,
                channel=Channel.DEVICE,
                platforms=[Platform.MACOS],
                auto_update=True,
            )
            asset = Asset.objects.create(
                adam_id="1234567890",
                pricing_param="STDQ",
                bundle_id=bundle_id or "com.acme.myenterpriseapp",
                product_type=Asset.ProductType.APP,
                device_assignable=True,
                revocable=True,
                supported_platforms=[Platform.MACOS],
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
            location_asset = LocationAsset.objects.create(
                asset=asset,
                location=location
            )
        else:
            location_asset = artifact.artifactversion_set.first().store_app.location_asset
        artifact_version = ArtifactVersion.objects.create(
            artifact=artifact,
            version=version or 0,
            macos=True,
        )
        store_app = StoreApp.objects.create(
            artifact_version=artifact_version, location_asset=location_asset
        )
        if status:
            DeviceArtifact.objects.create(
                enrolled_device=self.enrolled_device,
                artifact_version=artifact_version,
                status=status,
            )
        if in_blueprint:
            BlueprintArtifact.objects.get_or_create(
                blueprint=self.blueprint,
                artifact=artifact,
                defaults={"macos": True},
            )
            update_blueprint_serialized_artifacts(self.blueprint)
        return artifact_version, store_app

    # verify_channel_and_device

    def test_scope(self):
        for channel, platform, user_enrollment, result in (
            (Channel.DEVICE, Platform.IOS, False, True),
            (Channel.DEVICE, Platform.IPADOS, False, True),
            (Channel.DEVICE, Platform.MACOS, False, True),
            (Channel.DEVICE, Platform.TVOS, False, True),
            (Channel.USER, Platform.IOS, False, False),
            (Channel.USER, Platform.IPADOS, False, False),
            (Channel.USER, Platform.MACOS, False, False),
            (Channel.USER, Platform.TVOS, False, False),
            (Channel.DEVICE, Platform.IOS, True, True),
            (Channel.DEVICE, Platform.IPADOS, True, False),
            (Channel.DEVICE, Platform.MACOS, True, False),
            (Channel.DEVICE, Platform.TVOS, True, False),
            (Channel.USER, Platform.IOS, True, False),
            (Channel.USER, Platform.IPADOS, True, False),
            (Channel.USER, Platform.MACOS, True, False),
            (Channel.USER, Platform.TVOS, True, False),
        ):
            self.enrolled_device.platform = platform
            self.enrolled_device.user_enrollment = user_enrollment
            self.assertEqual(
                result,
                RemoveApplication.verify_channel_and_device(
                    channel, self.enrolled_device
                ),
            )

    # build_command

    def test_build_command(self):
        artifact_version, store_app = self._force_store_app()
        cmd = RemoveApplication.create_for_device(
            self.enrolled_device, artifact_version
        )
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(
            payload,
            {
                "RequestType": "RemoveApplication",
                "Identifier": store_app.location_asset.asset.bundle_id,
            },
        )

    def test_build_command_error(self):
        artifact_version, store_app = self._force_store_app()
        store_app.location_asset.asset.bundle_id = None
        cmd = RemoveApplication.create_for_device(
            self.enrolled_device, artifact_version
        )
        with self.assertRaises(ValueError) as cm:
            cmd.build_http_response(self.dep_enrollment_session)
        self.assertEqual(
            cm.exception.args[0],
            f"Store app {store_app.pk} linked to asset without bundle ID",
        )

    # process_response

    @patch("zentral.contrib.mdm.apps_books.location_cache.get")
    def test_process_acknowledged_response(self, location_cache_get):
        client = Mock()
        client.post_device_disassociation.return_value = {"eventId": str(uuid.uuid4())}
        location_cache_get.return_value = (None, client)
        artifact_version, store_app = self._force_store_app(
            status=TargetArtifact.Status.INSTALLED
        )
        qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=artifact_version.artifact,
        )
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first().artifact_version, artifact_version)
        cmd = RemoveApplication.create_for_device(
            self.enrolled_device, artifact_version
        )
        cmd.process_response(
            {"Status": "Acknowledged"}, self.dep_enrollment_session, self.mbu
        )
        self.assertEqual(qs.count(), 1)
        ta = qs.first()
        self.assertEqual(ta.status, TargetArtifact.Status.UNINSTALLED)
        location_cache_get.assert_called_once_with(store_app.location_asset.location.mdm_info_id)
        client.post_device_disassociation.assert_called_once_with(self.enrolled_device.serial_number,
                                                                  store_app.location_asset.asset)

    @patch("zentral.contrib.mdm.apps_books.location_cache.get")
    @patch("zentral.contrib.mdm.commands.remove_application.logger.exception")
    def test_process_acknowledged_response_client_exception(self, logger_exception, location_cache_get):
        client = Mock()
        client.post_device_disassociation.side_effect = KeyError
        location_cache_get.return_value = (None, client)
        artifact_version, store_app = self._force_store_app(
            status=TargetArtifact.Status.INSTALLED
        )
        qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=artifact_version.artifact,
        )
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first().artifact_version, artifact_version)
        cmd = RemoveApplication.create_for_device(
            self.enrolled_device, artifact_version
        )
        cmd.process_response(
            {"Status": "Acknowledged"}, self.dep_enrollment_session, self.mbu
        )
        self.assertEqual(qs.count(), 1)
        ta = qs.first()
        self.assertEqual(ta.status, TargetArtifact.Status.UNINSTALLED)
        location_asset = store_app.location_asset
        location = location_asset.location
        asset = location_asset.asset
        location_cache_get.assert_called_once_with(location.mdm_info_id)
        client.post_device_disassociation.assert_called_once_with(self.enrolled_device.serial_number, asset)
        logger_exception.assert_called_once_with(
            "enrolled device %s asset %s/%s/%s: could not post disassociation",
            self.enrolled_device.serial_number, location.name, asset.adam_id, asset.pricing_param
        )

    @patch("zentral.contrib.mdm.apps_books.location_cache.get")
    @patch("zentral.contrib.mdm.commands.remove_application.logger.warning")
    def test_process_acknowledged_response_no_event_id(self, logger_warning, location_cache_get):
        client = Mock()
        client.post_device_disassociation.return_value = {}
        location_cache_get.return_value = (None, client)
        artifact_version, store_app = self._force_store_app(
            status=TargetArtifact.Status.INSTALLED
        )
        qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=artifact_version.artifact,
        )
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first().artifact_version, artifact_version)
        cmd = RemoveApplication.create_for_device(
            self.enrolled_device, artifact_version
        )
        cmd.process_response(
            {"Status": "Acknowledged"}, self.dep_enrollment_session, self.mbu
        )
        self.assertEqual(qs.count(), 1)
        ta = qs.first()
        self.assertEqual(ta.status, TargetArtifact.Status.UNINSTALLED)
        location_asset = store_app.location_asset
        location = location_asset.location
        asset = location_asset.asset
        location_cache_get.assert_called_once_with(location.mdm_info_id)
        client.post_device_disassociation.assert_called_once_with(self.enrolled_device.serial_number, asset)
        logger_warning.assert_called_once_with(
            "enrolled device %s asset %s/%s/%s: disassociation response without eventId",
            self.enrolled_device.serial_number, location.name, asset.adam_id, asset.pricing_param
        )

    # _remove_artifacts

    def test_remove_application_noop(self):
        artifact_version, _ = self._force_store_app(
            status=TargetArtifact.Status.INSTALLED, in_blueprint=True
        )
        self.assertIsNone(
            _remove_artifacts(
                Target(self.enrolled_device),
                self.dep_enrollment_session,
                RequestStatus.IDLE,
            )
        )

    def test_remove_application_notnow_noop(self):
        artifact_version, _ = self._force_store_app(
            status=TargetArtifact.Status.INSTALLED
        )
        self.assertIsNone(
            _remove_artifacts(
                Target(self.enrolled_device),
                self.dep_enrollment_session,
                RequestStatus.NOT_NOW,
            )
        )

    def test_remove_application(self):
        artifact_version, _ = self._force_store_app(
            status=TargetArtifact.Status.INSTALLED
        )
        command = _remove_artifacts(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(command, RemoveApplication)
        self.assertEqual(command.channel, Channel.DEVICE)
        self.assertEqual(command.artifact_version, artifact_version)

    def test_remove_application_previous_error_noop(self):
        self._force_store_app(status=TargetArtifact.Status.INSTALLED)
        command = _remove_artifacts(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        command.process_response(
            {"Status": "Error", "ErrorChain": [{"un": 1}]},
            self.dep_enrollment_session,
            self.mbu,
        )
        self.assertIsNone(
            _remove_artifacts(
                Target(self.enrolled_device),
                self.dep_enrollment_session,
                RequestStatus.IDLE,
            )
        )

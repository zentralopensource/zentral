import datetime
import plistlib
import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.artifacts import Target, update_blueprint_serialized_artifacts
from zentral.contrib.mdm.commands import InstallApplication, ManagedApplicationList
from zentral.contrib.mdm.commands.base import load_command
from zentral.contrib.mdm.commands.scheduling import _install_artifacts
from zentral.contrib.mdm.models import (Artifact, ArtifactVersion,
                                        Asset, Blueprint, BlueprintArtifact, Channel,
                                        DeviceArtifact, DeviceAssignment, DeviceCommand,
                                        Location, LocationAsset,
                                        Platform, RequestStatus, StoreApp,
                                        TargetArtifact)
from .utils import force_dep_enrollment_session


class InstallApplicationCommandTestCase(TestCase):
    maxDiff = None

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
        cls.enrolled_device = cls.dep_enrollment_session.enrolled_device
        cls.blueprint = Blueprint.objects.create(name=get_random_string(12))
        cls.enrolled_device.blueprint = cls.blueprint
        cls.enrolled_device.save()
        cls.artifact = Artifact.objects.create(
            name=get_random_string(32),
            type=Artifact.Type.STORE_APP,
            channel=Channel.DEVICE,
            platforms=[Platform.MACOS],
            auto_update=True,
        )
        cls.artifact_version0 = ArtifactVersion.objects.create(
            artifact=cls.artifact,
            version=0,
            macos=True,
        )
        DeviceArtifact.objects.create(
            enrolled_device=cls.enrolled_device,
            artifact_version=cls.artifact_version0,
            status=TargetArtifact.Status.INSTALLED,
        )
        BlueprintArtifact.objects.get_or_create(
            blueprint=cls.blueprint,
            artifact=cls.artifact,
            defaults={"macos": True},
        )
        cls.artifact_version = ArtifactVersion.objects.create(
            artifact=cls.artifact,
            version=1,
            macos=True,
        )
        cls.asset = Asset.objects.create(
            adam_id="1234567890",
            pricing_param="STDQ",
            product_type=Asset.ProductType.APP,
            device_assignable=True,
            revocable=True,
            supported_platforms=[Platform.MACOS]
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
        cls.location_asset = LocationAsset.objects.create(
            asset=cls.asset,
            location=location
        )
        cls.store_app0 = StoreApp.objects.create(
            artifact_version=cls.artifact_version0,
            location_asset=cls.location_asset
        )
        cls.store_app = StoreApp.objects.create(
            artifact_version=cls.artifact_version,
            location_asset=cls.location_asset,
            associated_domains=["un.example.com", "deux.example.com"],
            associated_domains_enable_direct_downloads=True,
            removable=True,
            vpn_uuid="a6ce58b6-3532-41a3-ac07-25e8ffb24849",
            content_filter_uuid="9f0d5335-0434-46d0-9ffb-5c61f2cda2da",
            dns_proxy_uuid="df3ab72e-7028-4120-b926-500e77d5f80d",
            configuration=plistlib.dumps({"Yolo": "Fomo $ENROLLED_DEVICE.SERIAL_NUMBER"}),
            remove_on_unenroll=True,
            prevent_backup=True,
        )
        update_blueprint_serialized_artifacts(cls.blueprint)

    # verify_channel_and_device

    def test_scope(self):
        for channel, platform, user_enrollment, result in (
            (Channel.DEVICE, Platform.IOS, False, True),
            (Channel.DEVICE, Platform.IPADOS, False, True),
            (Channel.DEVICE, Platform.MACOS, False, True),
            (Channel.DEVICE, Platform.TVOS, False, True),
            (Channel.USER, Platform.IOS, False, False),
            (Channel.USER, Platform.IPADOS, False, False),
            (Channel.USER, Platform.MACOS, False, True),
            (Channel.USER, Platform.TVOS, False, False),
            (Channel.DEVICE, Platform.IOS, True, True),
            (Channel.DEVICE, Platform.IPADOS, True, True),
            (Channel.DEVICE, Platform.MACOS, True, True),
            (Channel.DEVICE, Platform.TVOS, True, False),
        ):
            self.enrolled_device.platform = platform
            self.enrolled_device.user_enrollment = user_enrollment
            self.assertEqual(
                result,
                InstallApplication.verify_channel_and_device(
                    channel, self.enrolled_device
                )
            )

    # build_command

    def test_build_command_user_enrollment_none(self):
        self.assertIsNone(self.enrolled_device.user_enrollment)
        cmd = InstallApplication.create_for_device(self.enrolled_device, self.artifact_version)
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(
            payload,
            {"RequestType": "InstallApplication",
             "iTunesStoreID": 1234567890,
             "InstallAsManaged": True,  # No ChangeManagementState
             "Options": {"PurchaseMethod": 1},
             "ManagementFlags": 5,
             "Attributes": {
                 "Removable": True,
                 "AssociatedDomains": ["un.example.com", "deux.example.com"],
                 "AssociatedDomainsEnableDirectDownloads": True,
                 "VPNUUID": "a6ce58b6-3532-41a3-ac07-25e8ffb24849",
                 "ContentFilterUUID": "9f0d5335-0434-46d0-9ffb-5c61f2cda2da",
                 "DNSProxyUUID": "df3ab72e-7028-4120-b926-500e77d5f80d",
             },
             "Configuration": {"Yolo": f"Fomo {self.enrolled_device.serial_number}"}}
        )

    def test_build_command_user_enrollment_false(self):
        self.enrolled_device.user_enrollment = False
        cmd = InstallApplication.create_for_device(self.enrolled_device, self.artifact_version)
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(
            payload,
            {"RequestType": "InstallApplication",
             "iTunesStoreID": 1234567890,
             "InstallAsManaged": True,
             "ChangeManagementState": "Managed",
             "Options": {"PurchaseMethod": 1},
             "ManagementFlags": 5,
             "Attributes": {
                 "Removable": True,
                 "AssociatedDomains": ["un.example.com", "deux.example.com"],
                 "AssociatedDomainsEnableDirectDownloads": True,
                 "VPNUUID": "a6ce58b6-3532-41a3-ac07-25e8ffb24849",
                 "ContentFilterUUID": "9f0d5335-0434-46d0-9ffb-5c61f2cda2da",
                 "DNSProxyUUID": "df3ab72e-7028-4120-b926-500e77d5f80d",
             },
             "Configuration": {"Yolo": f"Fomo {self.enrolled_device.serial_number}"}}
        )

    def test_build_command_user_enrollment_true(self):
        self.enrolled_device.user_enrollment = True
        cmd = InstallApplication.create_for_device(self.enrolled_device, self.artifact_version)
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(
            payload,
            {"RequestType": "InstallApplication",
             "iTunesStoreID": 1234567890,
             "InstallAsManaged": True,  # No ChangeManagementState
             "Options": {"PurchaseMethod": 1},
             "ManagementFlags": 5,
             "Attributes": {
                 "Removable": True,
                 "AssociatedDomains": ["un.example.com", "deux.example.com"],
                 "AssociatedDomainsEnableDirectDownloads": True,
                 "VPNUUID": "a6ce58b6-3532-41a3-ac07-25e8ffb24849",
                 "ContentFilterUUID": "9f0d5335-0434-46d0-9ffb-5c61f2cda2da",
                 "DNSProxyUUID": "df3ab72e-7028-4120-b926-500e77d5f80d",
             },
             "Configuration": {"Yolo": f"Fomo {self.enrolled_device.serial_number}"}}
        )

    # process_response

    def test_process_acknowledged_response_with_identifier(self):
        qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=self.artifact
        ).order_by("created_at")
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first().artifact_version, self.artifact_version0)
        cmd = InstallApplication.create_for_device(self.enrolled_device, self.artifact_version)
        cmd.process_response(
            {"Status": "Acknowledged",
             "State": "Installing",
             "Identifier": "com.example.app"},
            self.dep_enrollment_session,
            self.mbu
        )
        self.assertEqual(qs.count(), 2)
        da0, da1 = list(qs)
        self.assertEqual(da0.artifact_version, self.artifact_version0)
        self.assertEqual(da1.artifact_version, self.artifact_version)
        self.assertEqual(da1.status, TargetArtifact.Status.AWAITING_CONFIRMATION)
        qs = DeviceCommand.objects.filter(
            enrolled_device=self.enrolled_device,
            time__isnull=True
        )
        self.assertEqual(qs.count(), 1)
        db_cmd = qs.first()
        cmd = load_command(db_cmd)
        self.assertIsInstance(cmd, ManagedApplicationList)
        self.assertEqual(cmd.artifact_version, self.artifact_version)
        self.assertEqual(cmd.identifiers, ["com.example.app"])

    def test_process_acknowledged_response_without_identifier_asset_identifier(self):
        qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=self.artifact
        ).order_by("created_at")
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first().artifact_version, self.artifact_version0)
        self.asset.bundle_id = "com.example.app"  # Fallback
        cmd = InstallApplication.create_for_device(self.enrolled_device, self.artifact_version)
        cmd.process_response(
            {"Status": "Acknowledged",
             "State": "Installing"},
            self.dep_enrollment_session,
            self.mbu
        )
        self.assertEqual(qs.count(), 2)
        da0, da1 = list(qs)
        self.assertEqual(da0.artifact_version, self.artifact_version0)
        self.assertEqual(da1.artifact_version, self.artifact_version)
        self.assertEqual(da1.status, TargetArtifact.Status.AWAITING_CONFIRMATION)
        qs = DeviceCommand.objects.filter(
            enrolled_device=self.enrolled_device,
            time__isnull=True
        )
        self.assertEqual(qs.count(), 1)
        db_cmd = qs.first()
        cmd = load_command(db_cmd)
        self.assertIsInstance(cmd, ManagedApplicationList)
        self.assertEqual(cmd.artifact_version, self.artifact_version)
        self.assertEqual(cmd.identifiers, ["com.example.app"])

    def test_process_acknowledged_response_without_identifier_no_asset_identifier(self):
        qs = DeviceArtifact.objects.filter(
            enrolled_device=self.enrolled_device,
            artifact_version__artifact=self.artifact
        ).order_by("created_at")
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first().artifact_version, self.artifact_version0)
        cmd = InstallApplication.create_for_device(self.enrolled_device, self.artifact_version)
        cmd.process_response(
            {"Status": "Acknowledged",
             "State": "Installing"},
            self.dep_enrollment_session,
            self.mbu
        )
        self.assertEqual(qs.count(), 1)
        da = qs.first()
        self.assertEqual(da.artifact_version, self.artifact_version)
        self.assertEqual(da.status, TargetArtifact.Status.ACKNOWLEDGED)
        self.assertEqual(
            DeviceCommand.objects.filter(
                enrolled_device=self.enrolled_device,
                time__isnull=True
            ).count(),
            0
        )

    # _install_artifacts

    def test_install_artifacts_noop(self):
        target = Target(self.enrolled_device)
        self.assertIsNone(_install_artifacts(
            target,
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        ))
        self.assertEqual(
            target.missing_asset_assignments,
            [(str(self.location_asset.location.mdm_info_id), self.asset.adam_id, self.asset.pricing_param)]
        )

    def test_install_artifacts(self):
        DeviceAssignment.objects.create(
            location_asset=self.location_asset,
            serial_number=self.enrolled_device.serial_number
        )
        target = Target(self.enrolled_device)
        cmd = _install_artifacts(
            target,
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertIsInstance(cmd, InstallApplication)
        self.assertEqual(cmd.artifact_version, self.artifact_version)
        self.assertEqual(target.missing_asset_assignments, [])

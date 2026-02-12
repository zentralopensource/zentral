import datetime
import uuid
from io import StringIO
from unittest.mock import call, patch

from django.core.management import call_command
from django.test import TestCase
from django.utils.crypto import get_random_string

from zentral.contrib.mdm.dep_client import DEPClientError
from zentral.contrib.mdm.models import ACMEIssuer, Location, SCEPIssuer

from ..utils import force_dep_virtual_server


class MDMManagementCommandsTest(TestCase):

    # utils

    def _force_location(self, name=None):
        location = Location(
            server_token_hash=get_random_string(40, allowed_chars='abcdef0123456789'),
            server_token=get_random_string(12),
            server_token_expiration_date=datetime.date(2050, 1, 1),
            organization_name=get_random_string(12),
            country_code="DE",
            library_uid=str(uuid.uuid4()),
            name=name or get_random_string(12),
            platform="enterprisestore",
            website_url="https://business.apple.com",
            mdm_info_id=uuid.uuid4(),
        )
        location.set_notification_auth_token()
        location.save()
        location.refresh_from_db()
        return location

    # sync_apps_books

    @patch("zentral.contrib.mdm.management.commands.sync_apps_books.sync_assets")
    def test_sync_apps_books_defaults(self, sync_assets):
        location1 = self._force_location(name="yolo")
        location2 = self._force_location(name="fomo")
        out = StringIO()
        call_command('sync_apps_books', stdout=out)
        self.assertEqual(
            out.getvalue(),
            f"Sync apps & books for location {location2.pk} fomo\n"
            f"Sync apps & books for location {location1.pk} yolo\n"
        )
        sync_assets.assert_has_calls([
            call(location2), call(location1)
        ])

    @patch("zentral.contrib.mdm.management.commands.sync_apps_books.sync_assets")
    def test_sync_apps_books_list_locations(self, sync_assets):
        location1 = self._force_location(name="yolo")
        location2 = self._force_location(name="fomo")
        out = StringIO()
        call_command('sync_apps_books', '--list-locations', stdout=out)
        self.assertEqual(
            out.getvalue(),
            "Existing locations:\n"
            f"{location2.pk} fomo\n"
            f"{location1.pk} yolo\n"
        )
        sync_assets.assert_not_called()

    @patch("zentral.contrib.mdm.management.commands.sync_apps_books.sync_assets")
    def test_sync_apps_books_sync_one_location(self, sync_assets):
        self._force_location(name="yolo")
        location = self._force_location(name="fomo")
        out = StringIO()
        call_command('sync_apps_books', '--location', str(location.pk), stdout=out)
        self.assertEqual(
            out.getvalue(),
            f"Sync apps & books for location {location.pk} fomo\n"
        )
        sync_assets.assert_called_once_with(location)

    # sync_dep_devices

    @patch("zentral.contrib.mdm.management.commands.sync_dep_devices.sync_dep_virtual_server_devices")
    def test_sync_dep_devices_defaults(self, sync_dep_virtual_server_devices):
        dvs1 = force_dep_virtual_server()
        dvs2 = force_dep_virtual_server()
        sync_dep_virtual_server_devices.side_effect = [
            (("YOLO", True),),
            (("FOMO", False),),
        ]
        out = StringIO()
        call_command('sync_dep_devices', stdout=out)
        self.assertEqual(
            out.getvalue(),
            f"Sync server {dvs1.pk} {dvs1}\n"
            "Created YOLO\n"
            f"Sync server {dvs2.pk} {dvs2}\n"
            "Updated FOMO\n"
        )
        sync_dep_virtual_server_devices.assert_has_calls([
            call(dvs1, force_fetch=False), call(dvs2, force_fetch=False)
        ])

    @patch("zentral.contrib.mdm.management.commands.sync_dep_devices.sync_dep_virtual_server_devices")
    def test_sync_dep_devices_cursor_error(self, sync_dep_virtual_server_devices):
        dvs = force_dep_virtual_server()
        sync_dep_virtual_server_devices.side_effect = [
            DEPClientError("yolo", error_code="EXPIRED_CURSOR"),
            (("FOMO", False),),
        ]
        out = StringIO()
        call_command('sync_dep_devices', stdout=out)
        self.assertEqual(
            out.getvalue(),
            f"Sync server {dvs.pk} {dvs}\n"
            "Expired cursor → full sync\n"
            "Updated FOMO\n"
        )
        sync_dep_virtual_server_devices.assert_has_calls([
            call(dvs, force_fetch=False), call(dvs, force_fetch=True)
        ])

    @patch("zentral.contrib.mdm.management.commands.sync_dep_devices.sync_dep_virtual_server_devices")
    def test_sync_dep_devices_unknown_dep_client_error(self, sync_dep_virtual_server_devices):
        dvs = force_dep_virtual_server()
        sync_dep_virtual_server_devices.side_effect = DEPClientError("yolo", error_code="UNKNOWN")
        out = StringIO()
        err = StringIO()
        call_command('sync_dep_devices', stdout=out, stderr=err)
        self.assertEqual(
            out.getvalue(),
            f"Sync server {dvs.pk} {dvs}\n"
        )
        self.assertEqual(
            err.getvalue(),
            "DEP client error: yolo, error code: UNKNOWN\n"
        )
        sync_dep_virtual_server_devices.assert_called_once_with(dvs, force_fetch=False)

    @patch("zentral.contrib.mdm.management.commands.sync_dep_devices.sync_dep_virtual_server_devices")
    def test_sync_dep_devices_unknown_error(self, sync_dep_virtual_server_devices):
        dvs = force_dep_virtual_server()
        sync_dep_virtual_server_devices.side_effect = [
            ValueError("HAAAAAAAAAAA"),
            (("FOMO", False),),
        ]
        out = StringIO()
        err = StringIO()
        call_command('sync_dep_devices', stdout=out, stderr=err)
        self.assertEqual(
            out.getvalue(),
            f"Sync server {dvs.pk} {dvs}\n"
        )
        self.assertEqual(
            err.getvalue(),
            "Unknown error: HAAAAAAAAAAA\n"
        )
        sync_dep_virtual_server_devices.assert_called_once_with(dvs, force_fetch=False)

    @patch("zentral.contrib.mdm.management.commands.sync_dep_devices.sync_dep_virtual_server_devices")
    def test_sync_dep_devices_one_server(self, sync_dep_virtual_server_devices):
        force_dep_virtual_server()
        dvs = force_dep_virtual_server()
        sync_dep_virtual_server_devices.side_effect = [
            (("YOLO", True),),
        ]
        out = StringIO()
        call_command('sync_dep_devices', '--server', str(dvs.pk), stdout=out)
        self.assertEqual(
            out.getvalue(),
            f"Sync server {dvs.pk} {dvs}\n"
            "Created YOLO\n"
        )
        sync_dep_virtual_server_devices.assert_called_once_with(dvs, force_fetch=False)

    @patch("zentral.contrib.mdm.management.commands.sync_dep_devices.sync_dep_virtual_server_devices")
    def test_sync_dep_devices_full_sync(self, sync_dep_virtual_server_devices):
        dvs1 = force_dep_virtual_server()
        dvs2 = force_dep_virtual_server()
        sync_dep_virtual_server_devices.side_effect = [
            (("YOLO", True),),
            (("FOMO", False),),
        ]
        out = StringIO()
        call_command('sync_dep_devices', '--full-sync', stdout=out)
        self.assertEqual(
            out.getvalue(),
            f"Sync server {dvs1.pk} {dvs1}\n"
            "Created YOLO\n"
            f"Sync server {dvs2.pk} {dvs2}\n"
            "Updated FOMO\n"
        )
        sync_dep_virtual_server_devices.assert_has_calls([
            call(dvs1, force_fetch=True), call(dvs2, force_fetch=True)
        ])

    @patch("zentral.contrib.mdm.management.commands.sync_dep_devices.sync_dep_virtual_server_devices")
    def test_sync_dep_devices_list_servers(self, sync_dep_virtual_server_devices):
        dvs1 = force_dep_virtual_server()
        dvs2 = force_dep_virtual_server()
        out = StringIO()
        call_command('sync_dep_devices', '--list-servers', stdout=out)
        self.assertEqual(
            out.getvalue(),
            "Existing DEP virtual servers:\n"
            f"{dvs1.pk} {dvs1}\n"
            f"{dvs2.pk} {dvs2}\n"
        )
        sync_dep_virtual_server_devices.assert_not_called()

    # provisioning

    def test_scep_issuer_provisioning(self):
        aqs = ACMEIssuer.objects.all()
        sqs = SCEPIssuer.objects.all()
        self.assertEqual(aqs.count(), 0)
        self.assertEqual(sqs.count(), 0)
        call_command('provision')
        self.assertEqual(aqs.count(), 1)
        self.assertEqual(sqs.count(), 1)
        acme_issuer = aqs.first()
        scep_issuer = sqs.first()
        # tests/conf/base.json ACME issuer
        self.assertEqual(acme_issuer.name, "ACME issuer")
        self.assertEqual(acme_issuer.description, "ACME issuer description")
        self.assertEqual(acme_issuer.directory_url, "https://www.example.com/acme/")
        self.assertEqual(acme_issuer.key_size, 384)
        self.assertEqual(acme_issuer.key_type, "ECSECPrimeRandom")
        self.assertEqual(acme_issuer.usage_flags, 1)
        self.assertEqual(acme_issuer.extended_key_usage, ["1.3.6.1.5.5.7.3.2"])
        self.assertTrue(acme_issuer.hardware_bound is True)
        self.assertTrue(acme_issuer.attest is True)
        self.assertEqual(acme_issuer.backend, "STATIC_CHALLENGE")
        self.assertEqual(
            acme_issuer.get_backend_kwargs(),
            {"challenge": "Challenge"}
        )
        # tests/conf/base.json SCEP issuer
        self.assertEqual(scep_issuer.name, "SCEP issuer")
        self.assertEqual(scep_issuer.description, "SCEP issuer description")
        self.assertEqual(scep_issuer.url, "https://www.example.com/scep/")
        self.assertEqual(scep_issuer.key_size, 2048)
        self.assertEqual(scep_issuer.key_usage, 1)
        self.assertEqual(scep_issuer.backend, "MICROSOFT_CA")
        self.assertEqual(
            scep_issuer.get_backend_kwargs(),
            {"url": "https://www.example.com/ndes/",
             "username": "Yolo",
             "password": "Fomo"}
        )

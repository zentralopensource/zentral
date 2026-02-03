from io import StringIO
from unittest import mock
from unittest.mock import patch, MagicMock
from django.core.management import call_command
from django.test import TestCase
from zentral.contrib.inventory.models import MACAddressBlockAssignment


class InventoryManagementCommandsTest(TestCase):
    # cleanup inventory

    def test_cleanup_inventory_history(self):
        out = StringIO()
        call_command('cleanup_inventory_history', stdout=out)
        result = out.getvalue()
        self.assertIn('max date', result)
        self.assertIn('machine_snapshot_commit', result)

    def test_cleanup_inventory_history_quiet_legacy(self):
        out = StringIO()
        call_command('cleanup_inventory_history', '-q', stdout=out)
        self.assertEqual("", out.getvalue())

    def test_cleanup_inventory_history_v_0(self):
        out = StringIO()
        call_command('cleanup_inventory_history', '-v', '0', stdout=out)
        self.assertEqual("", out.getvalue())

    # full export

    def test_export_full_inventory(self):
        out = StringIO()
        call_command('export_full_inventory', stdout=out)
        result = out.getvalue()
        self.assertTrue(result.startswith("File: exports/full_inventory_export-"))
        self.assertTrue(result.endswith(".zip\n"))

    @patch("zentral.contrib.inventory.management.commands.export_full_inventory.file_storage_has_signed_urls")
    def test_export_full_inventory_download(self, file_storage_has_signed_urls):
        file_storage_has_signed_urls.return_value = True
        out = StringIO()
        call_command('export_full_inventory', stdout=out)
        result = out.getvalue()
        self.assertTrue(result.startswith("Download URL:"))
        self.assertTrue(result.endswith(".zip\n"))

    # import mac assigment

    def test_import_mac_assignments(self):
        out = StringIO()
        with mock.patch('requests.get') as mock_requests:
            side_effects = [
                ["Registry,Assignment,Organization Name,Organization Address",
                 'MA-L,286FB9,"Nokia Shanghai Bell Co., Ltd.",'
                 '"No.388 Ning Qiao Road,Jin Qiao Pudong Shanghai Shanghai   CN 201206 "'],
                ["Registry,Assignment,Organization Name,Organization Address",
                 'MA-M,C85CE27,SYNERGY SYSTEMS AND SOLUTIONS,'
                 '"A1526, GREEN FIELDS COLONY Faridabad HARYANA IN 121001 "'],
                ["Registry,Assignment,Organization Name,Organization Address",
                 'MA-S,8C1F64AFA,"DATA ELECTRONIC DEVICES, INC",32 NORTHWESTERN DR SALEM NH US 03079']
            ]
            mock_resp = MagicMock()
            mock_resp.text.splitlines.side_effect = side_effects
            mock_requests.return_value = mock_resp

            call_command('import_mac_assignments', '--verbosity', 0, stdout=out)
            self.assertEqual(3, MACAddressBlockAssignment.objects.count())

    # Debug inventory clients

    def test_debug_inventory_clients_list(self):
        out = StringIO()
        call_command('debug_inventory_clients', '--list-clients', stdout=out)
        result = out.getvalue()
        self.assertIn('Configured clients:', result)
        self.assertIn('key:', result)

    def test_debug_inventory_clients_client(self):

        out = StringIO()
        call_command('debug_inventory_clients', '--client', 0, stdout=out)
        result = out.getvalue()
        self.assertIn('2 MACHINES', result)
        self.assertIn('zentral.contrib.inventory.client', result)

    def test_debug_inventory_clients_client_serial(self):
        out = StringIO()
        call_command('debug_inventory_clients', '--client', 0, '--serial-number', '0123456789', stdout=out)
        result = out.getvalue()
        self.assertIn("'serial_number': '0123456789',", result)

from io import StringIO
from unittest.mock import patch
from django.core.management import call_command
from django.test import TestCase


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

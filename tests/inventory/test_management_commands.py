from io import StringIO
from django.core.management import call_command
from django.test import TestCase


class InventoryManagementCommandsTest(TestCase):
    def test_cleanup_inventory_history(self):
        out = StringIO()
        call_command('cleanup_inventory_history', stdout=out)
        result = out.getvalue()
        self.assertIn('min date', result)
        self.assertIn('machine_snapshot_commit', result)

    def test_cleanup_inventory_history_quiet_legacy(self):
        out = StringIO()
        call_command('cleanup_inventory_history', '-q', stdout=out)
        self.assertEqual("", out.getvalue())

    def test_cleanup_inventory_history_v_0(self):
        out = StringIO()
        call_command('cleanup_inventory_history', '-v', '0', stdout=out)
        self.assertEqual("", out.getvalue())

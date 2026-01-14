from io import StringIO
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from .utils import force_tenant


class IntuneManagementCommandsTest(TestCase):
    def test_intune_sync_list_tenant(self):
        tenant = force_tenant()
        out = StringIO()
        call_command('intune_sync', '--list-tenants', stdout=out)
        self.assertEqual(
            out.getvalue(),
            f"Name: {tenant.name} UUID: {tenant.tenant_id}\n",
        )

    def test_intune_sync_missing_tenant_id(self):
        with self.assertRaises(CommandError) as cm:
            call_command('intune_sync')
        self.assertEqual(cm.exception.args[0], "An Intune tenant_id is needed")

    def test_intune_sync_unknown_tenant_id(self):
        with self.assertRaises(CommandError) as cm:
            call_command('intune_sync', '--tenant', 'yolo')
        self.assertEqual(cm.exception.args[0], "Intune tenant with tenant_id yolo does not exist")

    def test_intune_sync_tenant(self):
        tenant = force_tenant()
        out = StringIO()
        call_command('intune_sync', '--tenant', tenant.tenant_id, stdout=out)
        r = out.getvalue()
        self.assertIn("status: FAILURE", r)

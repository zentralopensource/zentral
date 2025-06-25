from io import StringIO
import json
from django.core.management import call_command
from django.test import TestCase


class ListPermissionsManagementCommandsTest(TestCase):
    def test_json_output(self):
        out = StringIO()
        call_command('list_permissions', '--json', stdout=out)
        result = json.loads(out.getvalue())
        self.assertIsInstance(result, list)
        self.assertIn("mdm.view_blueprint", result)
        self.assertIn("mdm.change_blueprint", result)
        self.assertIn("mdm.view_filevault_prk", result)

    def test_json_output_no_custom_perms(self):
        out = StringIO()
        call_command('list_permissions', '--no-custom', '--json', stdout=out)
        result = json.loads(out.getvalue())
        self.assertIsInstance(result, list)
        self.assertIn("mdm.view_blueprint", result)
        self.assertIn("mdm.change_blueprint", result)
        self.assertNotIn("mdm.view_filevault_prk", result)

    def test_json_output_read_only_perms(self):
        out = StringIO()
        call_command('list_permissions', '--read-only', '--json', stdout=out)
        result = json.loads(out.getvalue())
        self.assertIsInstance(result, list)
        self.assertIn("mdm.view_blueprint", result)
        self.assertNotIn("mdm.change_blueprint", result)
        self.assertNotIn("mdm.view_filevault_prk", result)

    def test_text_output(self):
        out = StringIO()
        call_command('list_permissions', stdout=out)
        result = out.getvalue().splitlines()
        self.assertIsInstance(result, list)
        self.assertIn("mdm.view_blueprint", result)
        self.assertIn("mdm.change_blueprint", result)
        self.assertIn("mdm.view_filevault_prk", result)

from io import StringIO
import os.path
import tempfile
from django.core.management import call_command
from django.test import TestCase


class DumpViewsBaseManagementCommandsTest(TestCase):
    def test_dump_views_defaults(self):
        out = StringIO()
        call_command('dump_views', stdout=out)
        self.assertIn("'name': 'IndexView'", out.getvalue())

    def test_dump_views_xlsx(self):
        with tempfile.TemporaryDirectory() as tmpdirname:
            dest_file = os.path.join(tmpdirname, "yolo.xsls")
            self.assertFalse(os.path.exists(dest_file))
            call_command('dump_views', '--xlsx', os.path.join(tmpdirname, "yolo.xsls"))
            self.assertTrue(os.path.exists(dest_file))
            with open(dest_file, "rb") as f:
                self.assertEqual(f.read(4), b"PK\x03\x04")

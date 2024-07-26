import os
import tempfile
from django.core.management import call_command
from django.test import TestCase


class BuildCustomErrorPagesBaseManagementCommandsTest(TestCase):
    def test_default(self):
        with tempfile.TemporaryDirectory() as tmpdirname:
            with self.settings(
                STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage',
                STATIC_ROOT=tmpdirname,
            ):
                self.assertEqual(len(os.listdir(tmpdirname)), 0)
                call_command('build_custom_error_pages')
                for err_code in (400, 403, 404, 429, 500, 502, 503, 504):
                    self.assertTrue(
                        os.path.exists(
                            os.path.join(tmpdirname, "custom_error_pages", f"{err_code}.html")
                        )
                    )

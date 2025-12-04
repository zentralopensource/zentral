from django.test import SimpleTestCase
from zentral.utils.db import get_read_only_database
import warnings


class DBUtilsTestCase(SimpleTestCase):
    def test_get_read_only_database_default(self):
        self.assertEqual(get_read_only_database(), "default")

    def test_get_read_only_database_ro(self):
        with warnings.catch_warnings():
            warnings.filterwarnings('ignore', category=UserWarning)
            with self.settings(DATABASES={"ro": "YOLO"}):
                self.assertEqual(get_read_only_database(), "ro")

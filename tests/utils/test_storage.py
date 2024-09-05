from django.test import SimpleTestCase, override_settings
from zentral.utils.storage import file_storage_has_signed_urls


class StorageTestCase(SimpleTestCase):
    def test_file_storage_has_signed_urls_default(self):
        self.assertFalse(file_storage_has_signed_urls())

    @override_settings(STORAGES={"default": {"BACKEND": "storages.backends.s3.S3Storage"}})
    def test_file_storage_has_signed_urls_default_s3(self):
        self.assertTrue(file_storage_has_signed_urls())

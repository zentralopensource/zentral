from django.test import SimpleTestCase, override_settings
from zentral.utils.storage import file_storage_has_signed_urls, select_dist_storage


class StorageTestCase(SimpleTestCase):
    def test_file_storage_has_signed_urls_default(self):
        self.assertFalse(file_storage_has_signed_urls())

    @override_settings(STORAGES={"default": {"BACKEND": "storages.backends.s3.S3Storage"}})
    def test_file_storage_has_signed_urls_default_s3(self):
        self.assertTrue(file_storage_has_signed_urls())

    @override_settings(STORAGES={"default": {"BACKEND": "storages.backends.s3.S3Storage"},
                                 "dist": {"BACKEND": "django.core.files.storage.InMemoryStorage"}})
    def test_select_dist_storage(self):
        storage = select_dist_storage()
        self.assertEqual(storage.__class__.__name__, "InMemoryStorage")

    @override_settings(STORAGES={"default": {"BACKEND": "storages.backends.s3.S3Storage"},
                                 "yolo": {"BACKEND": "django.core.files.storage.InMemoryStorage"}})
    def test_select_dist_storage_fallback(self):
        storage = select_dist_storage()
        self.assertEqual(storage.__class__.__name__, "S3Storage")

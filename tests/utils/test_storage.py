from datetime import timedelta
from django.test import SimpleTestCase, override_settings
from zentral.utils.storage import (file_storage_has_signed_urls,
                                   file_storage_signed_url_expiration,
                                   select_dist_storage)


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

    # signed URL expiration

    def test_file_storage_signed_url_expiration_default(self):
        self.assertIsNone(file_storage_signed_url_expiration())

    @override_settings(STORAGES={"default": {"BACKEND": "storages.backends.s3.S3Storage",
                                             "OPTIONS": {"querystring_expire": 600}}})
    def test_file_storage_signed_url_expiration_s3(self):
        self.assertEqual(file_storage_signed_url_expiration(), timedelta(seconds=600))

    @override_settings(STORAGES={"default": {"BACKEND": "storages.backends.s3.S3Storage",
                                             "OPTIONS": {"querystring_auth": False}}})
    def test_file_storage_signed_url_expiration_s3_public_urls(self):
        self.assertIsNone(file_storage_signed_url_expiration())

    @override_settings(STORAGES={"default": {"BACKEND": "storages.backends.s3.S3Storage",
                                             "OPTIONS": {"querystring_expire": 0}}})
    def test_file_storage_signed_url_expiration_s3_no_expire(self):
        self.assertIsNone(file_storage_signed_url_expiration())

    @override_settings(STORAGES={"default": {"BACKEND": "storages.backends.gcloud.GoogleCloudStorage",
                                             "OPTIONS": {"expiration": timedelta(hours=2)}}})
    def test_file_storage_signed_url_expiration_gcs(self):
        self.assertEqual(file_storage_signed_url_expiration(), timedelta(hours=2))

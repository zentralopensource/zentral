import base64
import hashlib
from urllib.parse import parse_qs, urlparse

from django.core.files.storage import storages
from django.test import SimpleTestCase, override_settings
from zentral.utils.storage import (file_storage_has_presigned_uploads, file_storage_has_signed_urls,
                                   generate_presigned_put, select_dist_storage)


S3_STORAGE = {"default": {"BACKEND": "storages.backends.s3.S3Storage",
                          "OPTIONS": {"bucket_name": "zentral-tests",
                                      "access_key": "AKIAIOSFODNN7EXAMPLE",
                                      "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                                      "region_name": "us-east-1"}}}


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


SHA256 = hashlib.sha256(b"yolo").hexdigest()


class PresignedUploadTestCase(SimpleTestCase):
    def test_default_storage_cannot_presign_uploads(self):
        self.assertFalse(file_storage_has_presigned_uploads())

    @override_settings(STORAGES={"default": {"BACKEND": "storages.backends.s3.S3Storage"}})
    def test_s3_can_presign_uploads(self):
        self.assertTrue(file_storage_has_presigned_uploads())

    @override_settings(STORAGES={"default": {"BACKEND": "storages.backends.gcloud.GoogleCloudStorage"}})
    def test_gcs_signs_downloads_but_not_uploads(self):
        # narrower than file_storage_has_signed_urls on purpose: signing a download is a read of an
        # object we already have, signing an upload delegates a write
        self.assertTrue(file_storage_has_signed_urls())
        self.assertFalse(file_storage_has_presigned_uploads())

    @override_settings(STORAGES=S3_STORAGE)
    def test_generate_presigned_put_signs_with_sigv4(self):
        # the deployment sets no signature version, and us-east-1 is exactly where botocore would
        # otherwise presign with the legacy V2 query signature — which signs neither the length nor
        # the checksum. Everything below depends on this being V4.
        url, _ = generate_presigned_put("turbo/uploads/test", 4, "application/gzip", SHA256, 900)
        query = parse_qs(urlparse(url).query)
        self.assertEqual(query["X-Amz-Algorithm"], ["AWS4-HMAC-SHA256"])
        self.assertNotIn("AWSAccessKeyId", query)

    @override_settings(STORAGES=S3_STORAGE)
    def test_generate_presigned_put(self):
        url, headers = generate_presigned_put("turbo/uploads/test", 4, "application/gzip", SHA256, 900)
        self.assertEqual(headers["Content-Type"], "application/gzip")
        self.assertEqual(headers["Content-Length"], "4")
        self.assertEqual(headers["x-amz-checksum-sha256"],
                         base64.b64encode(hashlib.sha256(b"yolo").digest()).decode("ascii"))
        parsed = urlparse(url)
        self.assertEqual(parsed.path, "/turbo/uploads/test")
        query = parse_qs(parsed.query)
        self.assertEqual(query["X-Amz-Expires"], ["900"])
        # every header is SIGNED, none of them travels in the query string: the client cannot change
        # the size, the type or the digest without invalidating the signature
        signed = query["X-Amz-SignedHeaders"][0].split(";")
        for header in ("content-length", "content-type", "x-amz-checksum-sha256"):
            self.assertIn(header, signed)
        self.assertNotIn("x-amz-checksum-sha256", query)

    @override_settings(STORAGES={"default": {"BACKEND": "storages.backends.s3.S3Storage",
                                             "OPTIONS": dict(S3_STORAGE["default"]["OPTIONS"],
                                                             location="zentral")}})
    def test_generate_presigned_put_respects_the_storage_location(self):
        # the client writes where django-storages reads. S3Storage prefixes every key it touches with
        # `location`, so a presigned PUT built from the bare name would put the object outside the
        # namespace that exists(), delete(), url() and the verification HEAD all look in.
        url, _ = generate_presigned_put("turbo/uploads/test", 4, "application/gzip", SHA256, 900)
        self.assertEqual(urlparse(url).path, "/zentral/turbo/uploads/test")
        self.assertEqual(urlparse(storages["default"].url("turbo/uploads/test")).path,
                         "/zentral/turbo/uploads/test")

    @override_settings(STORAGES=S3_STORAGE)
    def test_generate_presigned_put_not_a_hex_sha256(self):
        with self.assertRaises(ValueError) as cm:
            generate_presigned_put("turbo/uploads/test", 4, "application/gzip", "yolo", 900)
        self.assertEqual(cm.exception.args[0], "Not a hex sha256: 'yolo'")

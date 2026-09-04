import base64
import hashlib
from urllib.parse import parse_qs, urlparse

from botocore.exceptions import ClientError
from botocore.stub import Stubber
from django.core.files.base import ContentFile
from django.core.files.storage import storages
from django.test import SimpleTestCase, TestCase, override_settings
from zentral.utils.storage import (_stat_client, file_storage_has_presigned_uploads,
                                   file_storage_has_signed_urls, generate_presigned_put,
                                   select_dist_storage, sha256_object, stat_object)


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


class StatObjectS3TestCase(SimpleTestCase):
    """The S3 branch, stubbed against the real service model — so a parameter S3 does not have, or a
    response member that is not one, fails here instead of in production."""

    def _stubbed(self):
        storage = storages.create_storage(S3_STORAGE["default"])
        # the client stat_object caches on the storage, primed with a stub before it can build one
        client = storage.connection.meta.client
        storage._zentral_stat_client = client
        return storage, Stubber(client)

    def test_the_stat_client_carries_its_own_ceiling(self):
        # the only test that builds the real client: everything below primes the cache with a stub,
        # so a typo in these kwargs would surface in production as an exception verify_upload
        # swallows into "undecided", with one log line to find it by
        client = _stat_client(storages.create_storage(S3_STORAGE["default"]))
        self.assertEqual(client.meta.config.connect_timeout, 2)
        self.assertEqual(client.meta.config.read_timeout, 5)
        # botocore stores retries as a TOTAL: asking for max_attempts=1 would have meant two
        self.assertEqual(client.meta.config.retries["total_max_attempts"], 1)

    @override_settings(STORAGES={"default": {"BACKEND": "storages.backends.s3.S3Storage",
                                             "OPTIONS": dict(S3_STORAGE["default"]["OPTIONS"],
                                                             location="zentral")}})
    def test_stat_object_looks_where_the_presign_wrote(self):
        # the same normalisation the presigned PUT signs. Without it the agent writes under the
        # prefix, this HEAD looks at the bucket root, S3 answers 404 — and `missing` is a verdict,
        # not an undecided answer, so it sticks.
        storage = storages.create_storage(
            dict(S3_STORAGE["default"],
                 OPTIONS=dict(S3_STORAGE["default"]["OPTIONS"], location="zentral")))
        storage._zentral_stat_client = storage.connection.meta.client
        stub = Stubber(storage.connection.meta.client)
        stub.add_response("head_object", {"ContentLength": 4},
                          {"Bucket": "zentral-tests", "Key": "zentral/turbo/uploads/test",
                           "ChecksumMode": "ENABLED"})
        with stub:
            self.assertEqual(stat_object("turbo/uploads/test", storage=storage)["size"], 4)

    def test_stat_object_asks_for_the_checksum_and_gets_hex_back(self):
        # HeadObject reports a checksum ONLY when the request asks for it. Without ChecksumMode the
        # response is silently checksum-free, and a comparison against it would pass for any object.
        storage, stub = self._stubbed()
        stub.add_response(
            "head_object",
            {"ContentLength": 4, "ChecksumSHA256": base64.b64encode(hashlib.sha256(b"yolo").digest()).decode()},
            {"Bucket": "zentral-tests", "Key": "turbo/uploads/test", "ChecksumMode": "ENABLED"},
        )
        with stub:
            stored = stat_object("turbo/uploads/test", storage=storage)
        self.assertEqual(stored["size"], 4)
        # hex, the encoding the wire carries, not the base64 S3 reports
        self.assertEqual(stored["sha256"], hashlib.sha256(b"yolo").hexdigest())

    def test_stat_object_missing_key(self):
        # HeadObject has no body to carry an error code, so a missing key surfaces as the bare status
        # 404 — an `except NoSuchKey` would never fire
        storage, stub = self._stubbed()
        stub.add_client_error("head_object", service_error_code="404", http_status_code=404)
        with stub:
            self.assertIsNone(stat_object("turbo/uploads/gone", storage=storage))

    def test_stat_object_forbidden_is_not_missing(self):
        # a key we may not read is not an object that is not there, and recording it as missing would
        # blame the agent for a bucket policy
        storage, stub = self._stubbed()
        stub.add_client_error("head_object", service_error_code="403", http_status_code=403)
        with stub, self.assertRaises(ClientError):
            stat_object("turbo/uploads/test", storage=storage)

    def test_stat_object_without_a_stored_checksum(self):
        # an object something else wrote: the size is all the stat can say
        storage, stub = self._stubbed()
        stub.add_response("head_object", {"ContentLength": 4},
                          {"Bucket": "zentral-tests", "Key": "k", "ChecksumMode": "ENABLED"})
        with stub:
            stored = stat_object("k", storage=storage)
        self.assertEqual(stored, {"size": 4, "sha256": None, "crc64nvme": None})

    def test_stat_object_composite_checksum_is_not_a_sha256(self):
        # S3 reports a multipart composite checksum with a part-count suffix, which is not the digest
        # of the object and must not be compared against one
        storage, stub = self._stubbed()
        composite = base64.b64encode(hashlib.sha256(b"yolo").digest()).decode() + "-3"
        stub.add_response("head_object", {"ContentLength": 4, "ChecksumSHA256": composite},
                          {"Bucket": "zentral-tests", "Key": "k", "ChecksumMode": "ENABLED"})
        with stub:
            self.assertIsNone(stat_object("k", storage=storage)["sha256"])


class StatObjectLocalTestCase(TestCase):
    """The branch for a storage that signs nothing and records no digest of its own."""

    def _store(self, key, body):
        storage = storages["default"]
        storage.save(key, ContentFile(body))
        self.addCleanup(storage.delete, key)
        return storage

    def test_stat_object_reports_the_size_and_no_digest(self):
        storage = self._store("turbo/uploads/stat-test", b"yolo")
        self.assertEqual(stat_object("turbo/uploads/stat-test", storage=storage),
                         {"size": 4, "sha256": None, "crc64nvme": None})

    def test_stat_object_missing_file(self):
        self.assertIsNone(stat_object("turbo/uploads/never-written", storage=storages["default"]))

    def test_both_helpers_default_to_the_default_storage(self):
        self._store("turbo/uploads/default-storage", b"yolo")
        self.assertEqual(stat_object("turbo/uploads/default-storage"),
                         {"size": 4, "sha256": None, "crc64nvme": None})
        self.assertEqual(sha256_object("turbo/uploads/default-storage"),
                         hashlib.sha256(b"yolo").hexdigest())

    def test_sha256_object(self):
        storage = self._store("turbo/uploads/hash-test", b"yolo" * 1024)
        self.assertEqual(sha256_object("turbo/uploads/hash-test", storage=storage),
                         hashlib.sha256(b"yolo" * 1024).hexdigest())

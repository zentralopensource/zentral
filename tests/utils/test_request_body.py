import gzip
import zlib

from django.test import RequestFactory, SimpleTestCase, override_settings

from zentral.utils.http import (
    Compression,
    InvalidCompressedBody,
    RequestBodyTooLarge,
    UnsupportedContentEncoding,
    read_request_body,
)


ENCODINGS = {"zlib": Compression.ZLIB, "gzip": Compression.GZIP}


class ReadRequestBodyTestCase(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def _request(self, body, content_encoding=None):
        headers = {}
        if content_encoding is not None:
            headers["Content-Encoding"] = content_encoding
        return self.factory.post("/", body, content_type="application/json", headers=headers)

    def test_no_content_encoding(self):
        self.assertEqual(read_request_body(self._request(b"yolo"), ENCODINGS), b"yolo")

    def test_empty_body_no_content_encoding(self):
        self.assertEqual(read_request_body(self._request(b""), ENCODINGS), b"")

    def test_identity(self):
        self.assertEqual(read_request_body(self._request(b"yolo", " Identity "), ENCODINGS), b"yolo")

    def test_zlib(self):
        request = self._request(zlib.compress(b"yolo"), "zlib")
        self.assertEqual(read_request_body(request, ENCODINGS), b"yolo")

    def test_gzip(self):
        request = self._request(gzip.compress(b"yolo"), "gzip")
        self.assertEqual(read_request_body(request, ENCODINGS), b"yolo")

    def test_content_encoding_case_and_spaces(self):
        request = self._request(gzip.compress(b"yolo"), " GZIP ")
        self.assertEqual(read_request_body(request, ENCODINGS), b"yolo")

    def test_encoding_mapped_to_another_compression(self):
        request = self._request(zlib.compress(b"yolo"), "gzip")
        self.assertEqual(read_request_body(request, {"gzip": Compression.ZLIB}), b"yolo")

    def test_unsupported_content_encoding(self):
        request = self._request(zlib.compress(b"yolo"), "br")
        with self.assertRaises(UnsupportedContentEncoding) as cm:
            read_request_body(request, ENCODINGS)
        self.assertEqual(cm.exception.status, 415)

    def test_not_accepted_content_encoding(self):
        request = self._request(gzip.compress(b"yolo"), "gzip")
        with self.assertRaises(UnsupportedContentEncoding):
            read_request_body(request, {"zlib": Compression.ZLIB})

    def test_invalid_compressed_body(self):
        for content_encoding in ENCODINGS:
            with self.subTest(content_encoding=content_encoding):
                with self.assertRaises(InvalidCompressedBody) as cm:
                    read_request_body(self._request(b"not compressed", content_encoding), ENCODINGS)
                self.assertEqual(cm.exception.status, 400)

    def test_wrong_compression(self):
        request = self._request(gzip.compress(b"yolo"), "zlib")
        with self.assertRaises(InvalidCompressedBody):
            read_request_body(request, ENCODINGS)

    def test_empty_compressed_body(self):
        with self.assertRaises(InvalidCompressedBody):
            read_request_body(self._request(b"", "zlib"), ENCODINGS)

    def test_truncated_compressed_body(self):
        request = self._request(zlib.compress(b"yolo" * 100)[:-4], "zlib")
        with self.assertRaises(InvalidCompressedBody):
            read_request_body(request, ENCODINGS)

    def test_data_after_compressed_body(self):
        request = self._request(zlib.compress(b"yolo") + b"fomo", "zlib")
        with self.assertRaises(InvalidCompressedBody):
            read_request_body(request, ENCODINGS)

    def test_second_gzip_member(self):
        request = self._request(gzip.compress(b"yolo") + gzip.compress(b"fomo"), "gzip")
        with self.assertRaises(InvalidCompressedBody):
            read_request_body(request, ENCODINGS)

    @override_settings(DATA_UPLOAD_MAX_MEMORY_SIZE=1024)
    def test_decompressed_body_at_limit(self):
        request = self._request(zlib.compress(b"a" * 1024), "zlib")
        self.assertEqual(read_request_body(request, ENCODINGS), b"a" * 1024)

    @override_settings(DATA_UPLOAD_MAX_MEMORY_SIZE=1024)
    def test_decompressed_body_too_large(self):
        for content_encoding, compress in (("zlib", zlib.compress), ("gzip", gzip.compress)):
            with self.subTest(content_encoding=content_encoding):
                body = compress(b"a" * 1025)
                self.assertLess(len(body), 1024)
                with self.assertRaises(RequestBodyTooLarge) as cm:
                    read_request_body(self._request(body, content_encoding), ENCODINGS)
                self.assertEqual(cm.exception.status, 413)

    @override_settings(DATA_UPLOAD_MAX_MEMORY_SIZE=None)
    def test_no_limit(self):
        request = self._request(zlib.compress(b"a" * 4096), "zlib")
        self.assertEqual(read_request_body(request, ENCODINGS), b"a" * 4096)

    @override_settings(DATA_UPLOAD_MAX_MEMORY_SIZE=16)
    def test_received_body_too_large(self):
        with self.assertRaises(RequestBodyTooLarge):
            read_request_body(self._request(b"a" * 17), ENCODINGS)

    @override_settings(DATA_UPLOAD_MAX_MEMORY_SIZE=16)
    def test_unsupported_content_encoding_body_not_read(self):
        request = self._request(b"a" * 17, "br")
        with self.assertRaises(UnsupportedContentEncoding):
            read_request_body(request, ENCODINGS)
        self.assertFalse(hasattr(request, "_body"))

    def test_max_size_received_body_at_limit(self):
        self.assertEqual(read_request_body(self._request(b"a" * 16), ENCODINGS, max_size=16), b"a" * 16)

    def test_max_size_received_body_too_large_not_read(self):
        request = self._request(b"a" * 17)
        with self.assertRaises(RequestBodyTooLarge):
            read_request_body(request, ENCODINGS, max_size=16)
        self.assertFalse(hasattr(request, "_body"))

    def test_max_size_decompressed_body_at_limit(self):
        request = self._request(zlib.compress(b"a" * 64), "zlib")
        self.assertEqual(read_request_body(request, ENCODINGS, max_size=64), b"a" * 64)

    def test_max_size_decompressed_body_too_large(self):
        body = zlib.compress(b"a" * 65)
        self.assertLess(len(body), 64)
        with self.assertRaises(RequestBodyTooLarge):
            read_request_body(self._request(body, "zlib"), ENCODINGS, max_size=64)

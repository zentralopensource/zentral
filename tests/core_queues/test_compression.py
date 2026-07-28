from base64 import b64encode
from datetime import datetime
import uuid
from compression import zstd
from django.test import SimpleTestCase
from kombu.utils import json
from zentral.core.queues.compression import (COMPRESSED_RAW_EVENT_KEY, COMPRESSION_MIN_SIZE,
                                             compress_raw_event_if_needed, decompress_raw_event)


def build_big_raw_event():
    return {"ms_tree": {"serial_number": "0123456789",
                        "osx_app_instances": [{"app": {"bundle_id": f"com.example.app{i}",
                                                       "bundle_name": f"App {i}",
                                                       "bundle_version": "1.2.3",
                                                       "bundle_version_str": "1.2.3"},
                                               "bundle_path": f"/Applications/App {i}.app"}
                                              for i in range(200)]}}


class RawEventCompressionTestCase(SimpleTestCase):
    maxDiff = None

    def test_small_raw_event_posted_as_is(self):
        raw_event = {"ms_tree": {"serial_number": "0123456789"}}
        self.assertIs(compress_raw_event_if_needed(raw_event), raw_event)

    def test_raw_event_under_the_threshold_posted_as_is(self):
        raw_event = {"ms_tree": ""}
        padding = COMPRESSION_MIN_SIZE - len(json.dumps(raw_event).encode("utf-8")) - 1
        raw_event["ms_tree"] = "y" * padding
        self.assertEqual(len(json.dumps(raw_event).encode("utf-8")), COMPRESSION_MIN_SIZE - 1)
        self.assertIs(compress_raw_event_if_needed(raw_event), raw_event)

    def test_raw_event_at_the_threshold_compressed(self):
        raw_event = {"ms_tree": ""}
        padding = COMPRESSION_MIN_SIZE - len(json.dumps(raw_event).encode("utf-8"))
        raw_event["ms_tree"] = "y" * padding
        self.assertEqual(len(json.dumps(raw_event).encode("utf-8")), COMPRESSION_MIN_SIZE)
        self.assertEqual(list(compress_raw_event_if_needed(raw_event)), [COMPRESSED_RAW_EVENT_KEY])

    def test_big_raw_event_compressed_and_inflated(self):
        raw_event = build_big_raw_event()
        serialized_size = len(json.dumps(raw_event).encode("utf-8"))
        self.assertGreater(serialized_size, COMPRESSION_MIN_SIZE)
        compressed_raw_event = compress_raw_event_if_needed(raw_event)
        self.assertEqual(list(compressed_raw_event), [COMPRESSED_RAW_EVENT_KEY])
        self.assertIsInstance(compressed_raw_event[COMPRESSED_RAW_EVENT_KEY], str)
        self.assertLess(len(json.dumps(compressed_raw_event).encode("utf-8")), serialized_size)
        self.assertEqual(decompress_raw_event(compressed_raw_event), raw_event)

    def test_payload_needs_no_json_escaping(self):
        # the base64 alphabet contains no character JSON escapes, so the wire size is the payload
        # plus the {"…":"…"} wrapper and nothing more — an encoding that needs escaping would cost
        # more on the wire than it saves
        compressed_raw_event = compress_raw_event_if_needed(build_big_raw_event())
        payload = compressed_raw_event[COMPRESSED_RAW_EVENT_KEY]
        self.assertEqual(len(json.dumps(compressed_raw_event).encode("utf-8")),
                         len(payload) + len(COMPRESSED_RAW_EVENT_KEY) + 8)

    def test_datetimes_and_uuids_survive_compression(self):
        raw_event = build_big_raw_event()
        raw_event["ms_tree"]["last_seen"] = datetime(2026, 7, 28, 12, 34, 56)
        raw_event["ms_tree"]["target"] = uuid.UUID("cae8b1c6-b1a5-4ea6-b1b3-5b7cd9a5e0f6")
        # the blob must inflate to exactly what an uncompressed raw event deserializes to,
        # whatever the registered kombu encoders make of those two types
        self.assertEqual(decompress_raw_event(compress_raw_event_if_needed(raw_event)),
                         json.loads(json.dumps(raw_event)))

    def test_decompress_uncompressed_raw_event_posted_as_is(self):
        raw_event = {"ms_tree": {"serial_number": "0123456789"}}
        self.assertIs(decompress_raw_event(raw_event), raw_event)

    def test_decompress_not_a_dict_posted_as_is(self):
        raw_event = ["yolo", "fomo"]
        self.assertIs(decompress_raw_event(raw_event), raw_event)

    def test_decompress_corrupted_payload_raises(self):
        with self.assertRaises(zstd.ZstdError):
            decompress_raw_event({COMPRESSED_RAW_EVENT_KEY: b64encode(b"not a zstd frame").decode("ascii")})

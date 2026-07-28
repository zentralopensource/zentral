import logging
from base64 import b64decode, b64encode
from compression import zstd
from kombu.utils import json


logger = logging.getLogger("zentral.core.queues.compression")


# Raw events travel as JSON, and SQS caps the message size — a cap it also applies to the sum of a
# whole send batch. Machine snapshot trees carrying a full app inventory go over it, and the queue
# rejects them. A raw event that big is posted as a single base64'd zstd blob under this key
# instead: iter_preprocessed_events inflates it, so the preprocessors only ever see the raw event
# the producer posted.
#
# base85 would shave 6% off the wire — nothing outside the pipeline reads these blobs — but
# b85encode/b85decode are pure Python where the base64 pair has a C fast path, and the decode lands
# on the preprocess worker: 6ms a blob there is not worth the 6%.
COMPRESSED_RAW_EVENT_KEY = "zstd_raw_event"

# Small raw events stay readable in the queue. The threshold is low enough that a full batch of
# messages at the threshold still fits well inside the limit for a single message, so a big tree
# can never take a batch over it on its own.
COMPRESSION_MIN_SIZE = 16 * 2**10


def compress_raw_event_if_needed(raw_event):
    # kombu's encoder, the one every backend serializes raw events with, so that the blob
    # deserializes into exactly the dict the preprocessor would have received uncompressed
    serialized_raw_event = json.dumps(raw_event).encode("utf-8")
    if len(serialized_raw_event) < COMPRESSION_MIN_SIZE:
        return raw_event
    payload = b64encode(zstd.compress(serialized_raw_event)).decode("ascii")
    logger.debug("Raw event compressed from %d to %d bytes", len(serialized_raw_event), len(payload))
    return {COMPRESSED_RAW_EVENT_KEY: payload}


def decompress_raw_event(raw_event):
    if not isinstance(raw_event, dict) or COMPRESSED_RAW_EVENT_KEY not in raw_event:
        return raw_event
    return json.loads(zstd.decompress(b64decode(raw_event[COMPRESSED_RAW_EVENT_KEY])))

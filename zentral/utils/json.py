from base64 import b64encode
from datetime import date, datetime, time
import json
import logging
import os
import uuid
from django.utils import timezone
from django.utils.text import get_valid_filename
from kombu.utils.json import register_type


logger = logging.getLogger("zentral.utils.json")


def register_kombu_json_encoders():
    """Last-resort net for datetimes & UUIDs that reach the event pipeline unserialized.

    Every queue and (almost) every store backend serializes with kombu's JSON encoder, which wraps a
    type it does not know in a {"__type__": …, "__value__": …} envelope instead of raising. Nothing
    breaks — the envelope round-trips inside Zentral — but the envelope lands in the stores that dump
    the event themselves (ClickHouse, Splunk, …), while the ES/OpenSearch client isoformats the same
    value, so one payload field ends up with two shapes depending on the backend.

    A None marker means "pure transformation, no envelope", so these encode to the plain strings a
    store expects. The registration order matters: datetime is a date subclass, and the encoder picks
    the first isinstance match, so registering date first would truncate datetimes to their date.

    kombu's own decoders stay registered, so events already enveloped in a queue keep deserializing.
    Serializing correctly at the source stays the rule — this only keeps a miss out of the stores.
    """
    register_type(datetime, None, datetime.isoformat)
    register_type(date, None, date.isoformat)
    register_type(time, None, time.isoformat)
    register_type(uuid.UUID, None, str)


def prepare_loaded_plist(obj):
    if isinstance(obj, bytes):
        obj = b64encode(obj).decode("ascii")
    elif isinstance(obj, datetime):
        obj = obj.isoformat()
    elif isinstance(obj, str):
        obj = obj.replace("\u0000", "")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            obj[k] = prepare_loaded_plist(v)
    elif isinstance(obj, list):
        obj = [prepare_loaded_plist(i) for i in obj]
    return obj


def remove_null_character(obj):
    if isinstance(obj, str):
        obj = obj.replace("\u0000", "")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            obj[k] = remove_null_character(v)
    elif isinstance(obj, list):
        obj = [remove_null_character(i) for i in obj]
    return obj


def save_dead_letter(data, file_suffix, directory="/tmp/zentral_dead_letters"):
    now = timezone.now()
    filename = "{}_{}.json".format(
        now.strftime("%Y-%m-%d_%H.%M.%S.%f"),
        file_suffix
    )
    dirpath = os.path.join(directory, now.strftime("%Y/%m/%d"))
    try:
        os.makedirs(dirpath, exist_ok=True)
        with open(os.path.join(dirpath, get_valid_filename(filename)), "w", encoding="utf-8") as f:
            json.dump(data, f, indent="  ")
    except Exception:
        logger.error("Could not save dead letter %s", file_suffix)

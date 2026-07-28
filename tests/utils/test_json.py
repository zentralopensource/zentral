import uuid
from datetime import date, datetime, time
from kombu.utils import json as kombu_json
from django.test import SimpleTestCase
from zentral.utils.json import prepare_loaded_plist, remove_null_character


class KombuJSONEncodersTestCase(SimpleTestCase):
    # zentral.core.events registers the encoders on import, and the events package is always loaded here

    def test_datetime_is_encoded_as_a_plain_string(self):
        self.assertEqual(
            kombu_json.dumps({"dt": datetime(1990, 2, 11, 8, 30, 15)}),
            '{"dt": "1990-02-11T08:30:15"}'
        )

    def test_datetime_keeps_its_time_and_offset(self):
        # datetime is a date subclass and the encoder takes the first isinstance match: were date
        # registered first, this would silently truncate to "2026-07-28"
        self.assertEqual(
            kombu_json.dumps({"dt": datetime.fromisoformat("2026-07-28T10:30:00+00:00")}),
            '{"dt": "2026-07-28T10:30:00+00:00"}'
        )

    def test_date_and_time_are_encoded_as_plain_strings(self):
        self.assertEqual(
            kombu_json.dumps({"d": date(2026, 7, 28), "t": time(10, 30)}),
            '{"d": "2026-07-28", "t": "10:30:00"}'
        )

    def test_uuid_is_encoded_as_a_plain_string(self):
        value = uuid.UUID("f6d47bd4-6b1c-4f0f-a6cb-1a0c19ba9b2f")
        self.assertEqual(
            kombu_json.dumps({"pk": value}),
            '{"pk": "f6d47bd4-6b1c-4f0f-a6cb-1a0c19ba9b2f"}'
        )

    def test_enveloped_datetime_still_deserializes(self):
        # kombu's decoders stay registered, so a message already in a queue keeps loading
        self.assertEqual(
            kombu_json.loads('{"dt": {"__type__": "datetime", "__value__": "1990-02-11T00:00:00"}}'),
            {"dt": datetime(1990, 2, 11)}
        )


class JsonUtilsTestCase(SimpleTestCase):
    def test_prepare_loaded_plist(self):
        self.assertEqual(
            prepare_loaded_plist({"un": b"un",
                                  "deux": 2,
                                  "trois": {1, 2, 3},
                                  4: ["1\u0000", b"deux", 3],
                                  "cinq": [{5: True,
                                            6: datetime(2000, 1, 1)}]}),
            {"un": "dW4=",
             "deux": 2,
             "trois": {1, 2, 3},
             4: ["1", "ZGV1eA==", 3],
             "cinq": [{5: True, 6: '2000-01-01T00:00:00'}]}
        )

    def test_remove_null_character(self):
        self.assertEqual(
            remove_null_character({"un": "1\u0000",
                                   "deux": 2,
                                   "trois": {1, 2, 3},
                                   4: [1, "de\u0000ux", 3],
                                   "cinq": [{5: True}]}),
            {"un": "1",
             "deux": 2,
             "trois": {1, 2, 3},
             4: [1, "deux", 3],
             "cinq": [{5: True}]}
        )

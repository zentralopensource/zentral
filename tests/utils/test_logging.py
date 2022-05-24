from collections import namedtuple
import json
import logging
from django.test import SimpleTestCase
from zentral.utils.logging import CustomJSONEncoder, DatadogJSONFormatter, JSONFormatter


class LoggingTestCase(SimpleTestCase):
    def test_custom_json_encoder(self):
        enc = CustomJSONEncoder()
        MyType = namedtuple("MyType", "un")
        self.assertEqual(enc.encode({"un": MyType(1)}), '{"un": [1]}')

    def test_datadog_json_formatter(self):
        fmt = DatadogJSONFormatter()
        rec = logging.makeLogRecord({"msg": "ceci est une erreur", "status_code": 400})
        msg = json.loads(fmt.format(rec))
        self.assertEqual(msg["message"], "ceci est une erreur")
        self.assertEqual(msg["http"]["status_code"], 400)

    def test_json_formatter(self):
        fmt = JSONFormatter()
        rec = logging.makeLogRecord({"msg": "ceci est une erreur", "status_code": 400})
        msg = json.loads(fmt.format(rec))
        self.assertEqual(msg["message"], "ceci est une erreur")
        self.assertEqual(msg["status_code"], 400)

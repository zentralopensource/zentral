from collections import namedtuple
import json
import logging
from django.test import RequestFactory, SimpleTestCase
from zentral.utils.logging import CustomJSONEncoder, DatadogJSONFormatter, JSONFormatter


class LoggingTestCase(SimpleTestCase):
    @staticmethod
    def build_request_with_credentials():
        return RequestFactory().get(
            "/public/munki/job_details/",
            HTTP_AUTHORIZATION="Bearer 8ceaf2d1a5b04e1cbf51b1c8e0e2e2f0",
            HTTP_COOKIE="sessionid=17f16b4e10b64b8f9e0d0e0a3e5e1c2b",
            HTTP_MDM_SIGNATURE="MIAGCSqGSIb3DQEHAqCAMIACAQExDzAN",
            HTTP_USER_AGENT="Zentral/1.2.3",
        )

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

    def test_json_formatter_redacts_sensitive_request_headers(self):
        request = self.build_request_with_credentials()
        fmt = JSONFormatter()
        rec = logging.makeLogRecord({"msg": "Forbidden", "status_code": 403, "request": request})
        # assert on the serialized record, to also catch a value leaked somewhere else in the payload
        formatted = fmt.format(rec)
        for secret in ("8ceaf2d1a5b04e1cbf51b1c8e0e2e2f0",
                       "17f16b4e10b64b8f9e0d0e0a3e5e1c2b",
                       "MIAGCSqGSIb3DQEHAqCAMIACAQExDzAN"):
            self.assertNotIn(secret, formatted)
        req = json.loads(formatted)["request"]
        for key in ("HTTP_AUTHORIZATION", "HTTP_COOKIE", "HTTP_MDM_SIGNATURE"):
            self.assertIn(key, req)
            self.assertEqual(req[key], "*" * 20)
        self.assertEqual(req["HTTP_USER_AGENT"], "Zentral/1.2.3")
        self.assertEqual(req["PATH_INFO"], "/public/munki/job_details/")

    def test_datadog_json_formatter_without_sensitive_request_headers(self):
        request = self.build_request_with_credentials()
        fmt = DatadogJSONFormatter()
        rec = logging.makeLogRecord({"msg": "Forbidden", "status_code": 403, "request": request})
        formatted = fmt.format(rec)
        for secret in ("8ceaf2d1a5b04e1cbf51b1c8e0e2e2f0",
                       "17f16b4e10b64b8f9e0d0e0a3e5e1c2b",
                       "MIAGCSqGSIb3DQEHAqCAMIACAQExDzAN"):
            self.assertNotIn(secret, formatted)
        msg = json.loads(formatted)
        self.assertEqual(msg["http"]["status_code"], 403)
        self.assertEqual(msg["http"]["useragent"], "Zentral/1.2.3")

from unittest.mock import patch

from django.test import SimpleTestCase
from requests import ConnectionError, Session

from zentral.utils.requests import CustomHTTPAdapter


class RequestsTestCase(SimpleTestCase):
    def test_custom_http_adapter_total(self):
        self.assertEqual(CustomHTTPAdapter(5, 2).max_retries.total, 2)

    @patch("urllib3.connectionpool.HTTPConnectionPool._make_request", side_effect=ConnectionResetError)
    def test_custom_http_adapter_attempts(self, make_request):
        for retries in (0, 1, 2):
            make_request.reset_mock()
            session = Session()
            session.mount("https://", CustomHTTPAdapter(10, retries))
            with patch("time.sleep"), self.assertRaises(ConnectionError):
                session.get("https://www.example.com")
            self.assertEqual(make_request.call_count, retries + 1)

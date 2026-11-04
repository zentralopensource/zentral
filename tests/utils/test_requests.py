from unittest.mock import patch

from django.test import SimpleTestCase
from requests import Response

from base.utils import deployment_info
from zentral.utils.requests import CustomHTTPAdapter, make_session


def ok_response():
    response = Response()
    response.status_code = 200
    return response


class RequestsTestCase(SimpleTestCase):
    def test_make_session_defaults(self):
        session = make_session()
        self.assertEqual(session.headers["User-Agent"], deployment_info.user_agent)
        for url in ("http://www.example.com", "https://www.example.com"):
            adapter = session.get_adapter(url)
            self.assertIsInstance(adapter, CustomHTTPAdapter)
            self.assertEqual(adapter.default_timeout, 10)
            self.assertEqual(adapter.max_retries.total, 2)

    def test_make_session_custom(self):
        adapter = make_session(timeout=3, max_retries=4).get_adapter("https://www.example.com")
        self.assertEqual(adapter.default_timeout, 3)
        self.assertEqual(adapter.max_retries.total, 5)

    @patch("requests.adapters.HTTPAdapter.send", return_value=ok_response())
    def test_make_session_default_timeout(self, send):
        make_session().get("https://www.example.com")
        self.assertEqual(send.call_args.kwargs["timeout"], 10)

    @patch("requests.adapters.HTTPAdapter.send", return_value=ok_response())
    def test_make_session_explicit_timeout(self, send):
        make_session().get("https://www.example.com", timeout=1)
        self.assertEqual(send.call_args.kwargs["timeout"], 1)

import http.server
import threading
from unittest.mock import patch

from django.test import SimpleTestCase
from requests import ConnectionError, Response, Session
from requests.exceptions import RetryError

from base.utils import deployment_info
from zentral.utils.requests import CustomHTTPAdapter, make_session


def ok_response():
    response = Response()
    response.status_code = 200
    return response


class StatusHandler(http.server.BaseHTTPRequestHandler):
    paths = []

    def do_GET(self):
        self.paths.append(self.path)
        status = int(self.path.strip("/"))
        self.send_response(status)
        if status in (429, 503):
            self.send_header("Retry-After", "3600")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


class RequestsTestCase(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), StatusHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join()
        super().tearDownClass()

    def setUp(self):
        StatusHandler.paths.clear()

    def test_make_session_defaults(self):
        session = make_session()
        self.assertEqual(session.headers["User-Agent"], deployment_info.user_agent)
        for url in ("http://www.example.com", "https://www.example.com"):
            adapter = session.get_adapter(url)
            self.assertIsInstance(adapter, CustomHTTPAdapter)
            self.assertEqual(adapter.default_timeout, 10)
            self.assertEqual(adapter.max_retries.total, 1)
            self.assertFalse(adapter.max_retries.raise_on_status)
            self.assertFalse(adapter.max_retries.respect_retry_after_header)

    def test_make_session_custom(self):
        adapter = make_session(timeout=3, max_retries=4).get_adapter("https://www.example.com")
        self.assertEqual(adapter.default_timeout, 3)
        self.assertEqual(adapter.max_retries.total, 4)

    def test_custom_http_adapter_defaults(self):
        adapter = CustomHTTPAdapter(5, 2)
        self.assertEqual(adapter.max_retries.total, 2)
        self.assertTrue(adapter.max_retries.raise_on_status)
        self.assertTrue(adapter.max_retries.respect_retry_after_header)

    @patch("urllib3.connectionpool.HTTPConnectionPool._make_request", side_effect=ConnectionResetError)
    def test_custom_http_adapter_attempts(self, make_request):
        for retries in (0, 1, 2):
            make_request.reset_mock()
            session = Session()
            session.mount("https://", CustomHTTPAdapter(10, retries))
            with patch("time.sleep"), self.assertRaises(ConnectionError):
                session.get("https://www.example.com")
            self.assertEqual(make_request.call_count, retries + 1)

    @patch("urllib3.connectionpool.HTTPConnectionPool._make_request", side_effect=ConnectionResetError)
    def test_make_session_attempts(self, make_request):
        for max_retries in (0, 1, 2):
            make_request.reset_mock()
            with patch("time.sleep"), self.assertRaises(ConnectionError):
                make_session(max_retries=max_retries).get("https://www.example.com")
            self.assertEqual(make_request.call_count, max_retries + 1)

    def test_make_session_last_response_after_retry(self):
        for status in (429, 500, 503):
            StatusHandler.paths.clear()
            with patch("time.sleep") as sleep:
                with make_session() as session:
                    response = session.get(f"{self.base_url}/{status}")
            self.assertEqual(response.status_code, status)
            self.assertEqual(StatusHandler.paths, [f"/{status}", f"/{status}"])
            sleep.assert_not_called()

    def test_custom_http_adapter_raises_after_retries(self):
        with patch("time.sleep") as sleep, self.assertRaises(RetryError):
            with make_session() as session:
                session.mount("http://", CustomHTTPAdapter(10, 1))
                session.get(f"{self.base_url}/503")
        self.assertEqual(StatusHandler.paths, ["/503", "/503"])
        sleep.assert_called_once_with(3600.0)

    @patch("requests.adapters.HTTPAdapter.send", return_value=ok_response())
    def test_make_session_default_timeout(self, send):
        make_session().get("https://www.example.com")
        self.assertEqual(send.call_args.kwargs["timeout"], 10)

    @patch("requests.adapters.HTTPAdapter.send", return_value=ok_response())
    def test_make_session_explicit_timeout(self, send):
        make_session().get("https://www.example.com", timeout=1)
        self.assertEqual(send.call_args.kwargs["timeout"], 1)

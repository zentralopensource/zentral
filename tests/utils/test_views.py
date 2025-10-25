import json
from django.http import HttpResponseServerError
from django.test import override_settings, RequestFactory, TestCase
from zentral.utils.views import server_error


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class ViewsTestCase(TestCase):
    maxDiff = None

    def setUp(self):
        self.factory = RequestFactory()

    def test_server_error_default(self):
        request = self.factory.get("/")
        response = server_error(request)
        self.assertIsInstance(response, HttpResponseServerError)
        self.assertEqual(response.headers["Content-Type"], "text/html; charset=utf-8")

    def test_server_error_scim(self):
        request = self.factory.get("/", headers={"Accept": "application/scim+json"})
        response = server_error(request)
        self.assertIsInstance(response, HttpResponseServerError)
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.headers["Content-Type"], "application/scim+json")
        self.assertEqual(
            json.loads(response.content),
            {'detail': 'Internal server error.',
             'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
             'status': 500}
        )

    def test_server_error_accept_json(self):
        request = self.factory.get("/", headers={"Accept": "application/json"})
        response = server_error(request)
        self.assertIsInstance(response, HttpResponseServerError)
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.headers["Content-Type"], "application/json")
        self.assertEqual(
            json.loads(response.content),
            {'error': 'Server Error (500)'}
        )

    def test_server_error_api(self):
        request = self.factory.get("/api/")
        response = server_error(request)
        self.assertIsInstance(response, HttpResponseServerError)
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.headers["Content-Type"], "application/json")
        self.assertEqual(
            json.loads(response.content),
            {'error': 'Server Error (500)'}
        )

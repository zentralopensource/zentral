from django.urls import reverse
from django.test import TestCase, override_settings
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class AccountUsersViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.pwd = "yo"
        cls.user = User.objects.create_user("yo", "yo@zentral.io", cls.pwd)
        cls.url = reverse("users:nginx_auth_request")

    # auth utils

    def log_user_in(self):
        response = self.client.post(reverse('login'),
                                    {'username': self.user.username, 'password': self.pwd},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["user"], self.user)

    def test_authenticated_ok(self):
        self.log_user_in()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

    def test_401(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 401)

    def test_ajax_403(self):
        response = self.client.get(self.url, HTTP_X_REQUESTED_WITH="Godzilla")
        self.assertEqual(response.status_code, 401)
        response = self.client.get(self.url, HTTP_X_REQUESTED_WITH="XMLHttpRequest")
        self.assertEqual(response.status_code, 403)

    def test_accept_json_403(self):
        response = self.client.get(self.url, HTTP_ACCEPT="text/html")
        self.assertEqual(response.status_code, 401)
        response = self.client.get(self.url, HTTP_ACCEPT="application/json;text/html")
        self.assertEqual(response.status_code, 403)

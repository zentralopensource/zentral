from django.urls import reverse
from django.test import TestCase, override_settings
from django.utils.crypto import get_random_string
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class OsquerySetupViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string())

    def login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def test_index_redirect(self):
        self.login_redirect(reverse("osquery:index"))

    def test_index(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("osquery:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/index.html")

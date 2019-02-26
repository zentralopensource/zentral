from django.urls import reverse
from django.test import TestCase, override_settings
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class JamfSetupViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.pwd = "godzillapwd"
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", cls.pwd)

    def login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def log_user_in(self):
        response = self.client.post(reverse('login'),
                                    {'username': self.user.username, 'password': self.pwd},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["user"], self.user)

    def log_user_out(self):
        response = self.client.get(reverse('logout'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["user"].is_authenticated, False)

    def test_jamf_instances_redirect(self):
        self.login_redirect(reverse("jamf:jamf_instances"))

    def test_jamf_instances_view(self):
        self.log_user_in()
        response = self.client.get(reverse("jamf:jamf_instances"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "jamf/jamfinstance_list.html")
        self.assertContains(response, "0 jamf instances")

    def test_create_jamf_instance_redirect(self):
        self.login_redirect(reverse("jamf:create_jamf_instance"))

    def test_create_jamf_instance_get(self):
        self.log_user_in()
        response = self.client.get(reverse("jamf:create_jamf_instance"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "jamf/jamfinstance_form.html")
        self.assertContains(response, "Create jamf instance")

    def create_jamf_instance(self):
        self.log_user_in()
        response = self.client.post(reverse("jamf:create_jamf_instance"),
                                    {"host": "yo.example.com",
                                     "port": 8443,
                                     "path": "/JSSResource",
                                     "user": "godzilla",
                                     "password": "pwd"},
                                    follow=True)
        object_list = response.context["object_list"]
        jamf_instance = object_list[0]
        self.assertEqual(jamf_instance.version, 0)
        return response, jamf_instance

    def test_create_jamf_instance_post(self):
        response, jamf_instance = self.create_jamf_instance()
        self.assertContains(response, "1 jamf instance")
        self.assertContains(response, "https://yo.example.com:8443/JSSResource")
        self.assertContains(response, "godzilla")
        self.assertNotContains(response, "pwd")

    def test_delete_jamf_instance_redirect(self):
        response, jamf_instance = self.create_jamf_instance()
        self.log_user_out()
        self.login_redirect(reverse("jamf:delete_jamf_instance", args=(jamf_instance.id,)))

    def test_delete_jamf_instance_get(self):
        _, jamf_instance = self.create_jamf_instance()
        response = self.client.get(reverse("jamf:delete_jamf_instance", args=(jamf_instance.id,)))
        self.assertContains(response, "Delete jamf instance")

    # TODO: def test_delete_jamf_instance_post(self):
    # PB: API calls!

    def test_setup_jamf_instance_redirect(self):
        _, jamf_instance = self.create_jamf_instance()
        self.log_user_out()
        self.login_redirect(reverse("jamf:setup_jamf_instance", args=(jamf_instance.id,)))

    def test_update_jamf_instance_redirect(self):
        _, jamf_instance = self.create_jamf_instance()
        self.log_user_out()
        self.login_redirect(reverse("jamf:update_jamf_instance", args=(jamf_instance.id,)))

    def test_update_jamf_instance_get(self):
        _, jamf_instance = self.create_jamf_instance()
        response = self.client.get(reverse("jamf:update_jamf_instance", args=(jamf_instance.id,)))
        self.assertContains(response, "Update jamf instance")

    def test_update_jamf_instance_post(self):
        _, jamf_instance = self.create_jamf_instance()
        response = self.client.post(reverse("jamf:update_jamf_instance", args=(jamf_instance.id,)),
                                    {"host": "yo.example2.com",
                                     "port": 8443,
                                     "path": "/JSSResource",
                                     "user": "godzilla",
                                     "password": "pwd"},
                                    follow=True)
        self.assertContains(response, "1 jamf instance")
        self.assertContains(response, "https://yo.example2.com:8443/JSSResource")
        jamf_instance = response.context["object_list"][0]
        self.assertEqual(jamf_instance.version, 1)

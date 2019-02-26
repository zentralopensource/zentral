from django.urls import reverse
from django.test import TestCase, override_settings
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class NagiosSetupViewsTestCase(TestCase):
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

    def test_nagios_instances_redirect(self):
        self.login_redirect(reverse("nagios:nagios_instances"))

    def test_nagios_instances_view(self):
        self.log_user_in()
        response = self.client.get(reverse("nagios:nagios_instances"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "nagios/nagiosinstance_list.html")
        self.assertContains(response, "0 nagios instances")

    def test_create_nagios_instance_redirect(self):
        self.login_redirect(reverse("nagios:create_nagios_instance"))

    def test_create_nagios_instance_get(self):
        self.log_user_in()
        response = self.client.get(reverse("nagios:create_nagios_instance"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "nagios/nagiosinstance_form.html")
        self.assertContains(response, "Create nagios instance")

    def create_nagios_instance(self):
        self.log_user_in()
        response = self.client.post(reverse("nagios:create_nagios_instance"),
                                    {"url": "https://godzilla.com/nagios3/"},
                                    follow=True)
        object_list = response.context["object_list"]
        nagios_instance = object_list[0]
        self.assertEqual(nagios_instance.version, 0)
        return response, nagios_instance

    def test_create_nagios_instance_post(self):
        response, nagios_instance = self.create_nagios_instance()
        self.assertContains(response, "1 nagios instance")
        self.assertContains(response, "https://godzilla.com/nagios3/")

    def test_delete_nagios_instance_redirect(self):
        response, nagios_instance = self.create_nagios_instance()
        self.log_user_out()
        self.login_redirect(reverse("nagios:delete_nagios_instance", args=(nagios_instance.id,)))

    def test_delete_nagios_instance_get(self):
        _, nagios_instance = self.create_nagios_instance()
        response = self.client.get(reverse("nagios:delete_nagios_instance", args=(nagios_instance.id,)))
        self.assertContains(response, "Delete nagios instance")

    def test_delete_nagios_instance_post(self):
        _, nagios_instance = self.create_nagios_instance()
        response = self.client.post(reverse("nagios:delete_nagios_instance", args=(nagios_instance.id,)),
                                    follow=True)
        self.assertContains(response, "0 nagios instances")

    def test_update_nagios_instance_redirect(self):
        _, nagios_instance = self.create_nagios_instance()
        self.log_user_out()
        self.login_redirect(reverse("nagios:update_nagios_instance", args=(nagios_instance.id,)))

    def test_update_nagios_instance_get(self):
        _, nagios_instance = self.create_nagios_instance()
        response = self.client.get(reverse("nagios:update_nagios_instance", args=(nagios_instance.id,)))
        self.assertContains(response, "Update nagios instance")

    def test_update_nagios_instance_post(self):
        _, nagios_instance = self.create_nagios_instance()
        response = self.client.post(reverse("nagios:update_nagios_instance", args=(nagios_instance.id,)),
                                    {"url": "https://godzilla2.com/nagios3/"},
                                    follow=True)
        self.assertContains(response, "1 nagios instance")
        self.assertContains(response, "https://godzilla2.com/nagios3/")
        nagios_instance = response.context["object_list"][0]
        self.assertEqual(nagios_instance.version, 1)

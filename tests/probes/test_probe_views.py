from django.urls import reverse
from django.test import TestCase, override_settings
from zentral.core.probes.models import ProbeSource
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class ProbeViewsTestCase(TestCase):
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

    def test_create_probe_get(self):
        url = reverse("probes:create")
        self.login_redirect(url)
        self.log_user_in()
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/probes/form.html")
        self.assertContains(response, "Create event probe")

    def test_create_probe_error(self):
        self.log_user_in()
        response = self.client.post(reverse("probes:create"), {})
        self.assertFormError(response, "form", "name", "This field is required.")

    def test_create_probe_post_redirect(self):
        url = reverse("probes:create")
        response = self.client.post(url,
                                    {"name": "234390824kjndjkhw",
                                     "event_types": ["zentral_login",
                                                     "zentral_logout"]},
                                    follow=True)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def create_probe(self, **kwargs):
        self.log_user_in()
        response = self.client.post(reverse("probes:create"),
                                    kwargs, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/probes/probe.html")
        self.assertIn("probe", response.context)
        probe = response.context["probe"]
        self.assertIn("object", response.context)
        probe_source = response.context["object"]
        return response, probe_source, probe

    def test_create_probe(self):
        self.log_user_in()
        kwargs = {"name": "2343908242",
                  "event_types": ["zentral_login",
                                  "zentral_logout"]}
        response, probe_source, probe = self.create_probe(**kwargs)
        self.assertEqual(probe.get_model(), "BaseProbe")
        self.assertEqual(probe.name, kwargs["name"])
        self.assertEqual(probe_source.name, kwargs["name"])
        self.assertEqual(probe_source.pk, probe.pk)

    def test_index(self):
        self.log_user_in()
        kwargs = {"name": "2343908242",
                  "event_types": ["zentral_login",
                                  "zentral_logout"]}
        _, probe_source, probe = self.create_probe(**kwargs)
        response = self.client.get(reverse("probes:index"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, kwargs["name"])
        probe_source.status = ProbeSource.ACTIVE
        probe_source.save()
        response = self.client.get(reverse("probes:index"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, kwargs["name"])

    def test_dashboard_redirect(self):
        self.log_user_in()
        kwargs = {"name": "2343908242",
                  "event_types": ["zentral_login",
                                  "zentral_logout"]}
        _, probe_source, probe = self.create_probe(**kwargs)
        self.log_user_out()
        url = reverse("probes:probe_dashboard", args=(probe.pk,))
        self.login_redirect(url)

    def test_dashboard_multi_event_types(self):
        self.log_user_in()
        kwargs = {"name": "2343908242",
                  "event_types": ["zentral_login",
                                  "zentral_logout"]}
        _, probe_source, probe = self.create_probe(**kwargs)
        url = reverse("probes:probe_dashboard", args=(probe.pk,))
        response = self.client.get(url)
        self.assertContains(response, "Events")
        self.assertContains(response, "Event types")

    def test_dashboard_single_event_type(self):
        self.log_user_in()
        kwargs = {"name": "2343908242",
                  "event_types": ["zentral_login"]}
        _, probe_source, probe = self.create_probe(**kwargs)
        url = reverse("probes:probe_dashboard", args=(probe.pk,))
        response = self.client.get(url)
        self.assertContains(response, "Events")
        self.assertNotContains(response, "Event types")

    def test_dashboard_data_redirect(self):
        self.log_user_in()
        kwargs = {"name": "2343908242",
                  "event_types": ["zentral_login"]}
        _, probe_source, probe = self.create_probe(**kwargs)
        self.log_user_out()
        url = reverse("probes:probe_dashboard_data", args=(probe.pk,))
        self.login_redirect(url)

    def test_dashboard_data_multi_event_types(self):
        self.log_user_in()
        kwargs = {"name": "2343908242",
                  "event_types": ["zentral_login",
                                  "zentral_logout"]}
        _, probe_source, probe = self.create_probe(**kwargs)
        url = reverse("probes:probe_dashboard_data", args=(probe.pk,))
        response = self.client.get(url)
        self.assertEqual(response["Content-Type"], "application/json")
        data = response.json()
        self.assertCountEqual(data, ["event_type", "created_at"])

    def test_dashboard_data_single_event_types(self):
        self.log_user_in()
        kwargs = {"name": "2343908242",
                  "event_types": ["zentral_login"]}
        _, probe_source, probe = self.create_probe(**kwargs)
        url = reverse("probes:probe_dashboard_data", args=(probe.pk,))
        response = self.client.get(url)
        self.assertEqual(response["Content-Type"], "application/json")
        data = response.json()
        self.assertCountEqual(data, ["created_at"])

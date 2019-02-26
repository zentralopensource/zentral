from django.urls import reverse
from django.test import TestCase, override_settings
from zentral.core.probes.models import ProbeSource
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MunkiInstallProbeViewsTestCase(TestCase):
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
        url = reverse("munki:create_install_probe")
        self.login_redirect(url)
        self.log_user_in()
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/probes/form.html")
        self.assertContains(response, "Create munki install probe")

    def test_create_probe_error(self):
        self.log_user_in()
        response = self.client.post(reverse("munki:create_install_probe"), {})
        self.assertFormError(response, "form", "install_types", "This field is required.")

    def test_create_probe_post_redirect(self):
        url = reverse("munki:create_install_probe")
        response = self.client.post(url, {"name": "io", "install_types": "removal"}, follow=True)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def create_probe(self, **kwargs):
        self.log_user_in()
        response = self.client.post(reverse("munki:create_install_probe"),
                                    kwargs,
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/install_probe.html")
        self.assertIn("probe", response.context)
        probe = response.context["probe"]
        self.assertIn("object", response.context)
        probe_source = response.context["object"]
        return response, probe_source, probe

    def test_create_probe(self):
        self.log_user_in()
        name = "munki godz"
        install_types = "removal"
        unattended_installs = '0'
        response, probe_source, probe = self.create_probe(name=name,
                                                          install_types=install_types,
                                                          unattended_installs=unattended_installs)
        self.assertEqual(probe.get_model(), "MunkiInstallProbe")
        self.assertEqual(probe.name, name)
        self.assertEqual(probe.unattended_installs, False)
        self.assertEqual(probe.install_types, set([install_types]))
        self.assertEqual(probe_source.name, name)
        self.assertEqual(probe_source.pk, probe.pk)
        self.assertContains(response, name)
        self.assertContains(response, install_types)

    def test_update_probe(self):
        self.log_user_in()
        name = "munki godz"
        install_types = "removal"
        unattended_installs = '0'
        response, probe_source, probe = self.create_probe(name=name,
                                                          install_types=install_types,
                                                          unattended_installs=unattended_installs)
        url = reverse("munki:update_install_probe", args=(probe.pk,))
        response = self.client.post(url, {"install_types": "install,removal"},
                                    follow=True)
        self.assertRedirects(response, "{}#munki".format(probe_source.get_absolute_url()))
        probe = response.context["probe"]
        self.assertEqual(probe.install_types, set(["install", "removal"]))
        self.assertContains(response, "install, removal")
        self.log_user_out()
        response = self.client.post(url, {"install_types": "install,removal"},
                                    follow=True)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def test_index(self):
        self.log_user_in()
        name = "munki godz"
        install_types = "removal"
        unattended_installs = '1'
        response, probe_source, probe = self.create_probe(name=name,
                                                          install_types=install_types,
                                                          unattended_installs=unattended_installs)
        response = self.client.get(reverse("probes:index"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, name)
        probe_source.status = ProbeSource.ACTIVE
        probe_source.save()
        response = self.client.get(reverse("probes:index"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, name)

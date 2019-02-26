from django.urls import reverse
from django.test import TestCase, override_settings
from zentral.core.probes.models import ProbeSource
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class OsqueryFIMProbeViewsTestCase(TestCase):
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

    def test_create_probe_get_redirect(self):
        self.login_redirect(reverse("osquery:create_fim_probe"))

    def test_create_probe_get(self):
        self.log_user_in()
        response = self.client.get(reverse("osquery:create_fim_probe"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/probes/form.html")
        self.assertContains(response, "Create osquery FIM probe")

    def test_create_probe_error(self):
        self.log_user_in()
        response = self.client.post(reverse("osquery:create_fim_probe"), {})
        self.assertFormError(response, "form", "file_path", "This field is required.")

    def test_create_probe_post_redirect(self):
        url = reverse("osquery:create_fim_probe")
        response = self.client.post(url, {"name": "234390824", "file_path": "/file_path_yo"}, follow=True)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def create_probe(self, **kwargs):
        self.log_user_in()
        response = self.client.post(reverse("osquery:create_fim_probe"),
                                    kwargs, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/fim_probe.html")
        self.assertIn("probe", response.context)
        probe = response.context["probe"]
        self.assertIn("object", response.context)
        probe_source = response.context["object"]
        return response, probe_source, probe

    def test_create_probe(self):
        self.log_user_in()
        name = "234390824"
        file_path = "/file_path_yo"
        response, probe_source, probe = self.create_probe(name=name, file_path=file_path)
        self.assertEqual(probe.get_model(), "OsqueryFIMProbe")
        self.assertEqual(probe.name, name)
        self.assertEqual(probe.file_paths[0].file_path, file_path)
        self.assertEqual(probe_source.name, name)
        self.assertEqual(probe_source.pk, probe.pk)
        self.assertNotContains(response, reverse("osquery:delete_fim_probe_file_path", args=(probe.pk, 0)))

    def test_index(self):
        self.log_user_in()
        name = "2343908241"
        file_path = "/file_path_yo"
        _, probe_source, probe = self.create_probe(name=name, file_path=file_path)
        response = self.client.get(reverse("probes:index"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, name)
        probe_source.status = ProbeSource.ACTIVE
        probe_source.save()
        response = self.client.get(reverse("probes:index"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, name)

    # file paths

    def test_add_file_path_get_redirect(self):
        self.log_user_in()
        _, _, probe = self.create_probe(name="name", file_path="yoooo")
        self.log_user_out()
        self.login_redirect(reverse("osquery:add_fim_probe_file_path", args=(probe.pk,)))

    def test_add_file_path_get(self):
        self.log_user_in()
        _, _, probe = self.create_probe(name="name", file_path="yoooo")
        response = self.client.get(reverse("osquery:add_fim_probe_file_path", args=(probe.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/file_path_form.html")
        self.assertContains(response, "Add osquery fim probe file path")

    def test_add_file_path_error(self):
        self.log_user_in()
        _, _, probe = self.create_probe(name="name", file_path="yoooo")
        response = self.client.post(reverse("osquery:add_fim_probe_file_path", args=(probe.pk,)), {})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, "form", "file_path", "This field is required.")

    def create_osquery_probe_with_extra_file_path(self, file_path):
        self.log_user_in()
        _, probe_source, probe = self.create_probe(name="name", file_path="un")
        response = self.client.post(reverse("osquery:add_fim_probe_file_path", args=(probe.pk,)),
                                    {"file_path": file_path},
                                    follow=True)
        self.assertRedirects(response, "{}#osquery_fim".format(probe_source.get_absolute_url()))
        return response, response.context["probe"], probe_source

    def test_add_file_path_post(self):
        self.log_user_in()
        response, probe, probe_source = self.create_osquery_probe_with_extra_file_path("42")
        self.assertEqual(len(probe.file_paths), 2)
        self.assertEqual(probe.file_paths[1].file_path, "42")
        self.assertContains(response, reverse("osquery:delete_fim_probe_file_path", args=(probe.pk, 0)))

    def test_update_file_path_get_redirect(self):
        self.log_user_in()
        _, probe, _ = self.create_osquery_probe_with_extra_file_path("42")
        self.log_user_out()
        self.login_redirect(reverse("osquery:update_fim_probe_file_path", args=(probe.pk, 0)))

    def test_update_file_path_get(self):
        self.log_user_in()
        response, probe, probe_source = self.create_osquery_probe_with_extra_file_path("42")
        self.assertContains(response, reverse("osquery:update_fim_probe_file_path", args=(probe.pk, 0)))
        self.assertContains(response, reverse("osquery:update_fim_probe_file_path", args=(probe.pk, 1)))
        response = self.client.get(reverse("osquery:update_fim_probe_file_path", args=(probe.pk, 0)))
        self.assertContains(response, "Update osquery fim probe file path")

    def test_update_file_path_post(self):
        self.log_user_in()
        response, probe, probe_source = self.create_osquery_probe_with_extra_file_path("42")
        updated_file_path = "48"
        response = self.client.post(reverse("osquery:update_fim_probe_file_path", args=(probe.pk, 0)),
                                    {"file_path": updated_file_path},
                                    follow=True)
        self.assertRedirects(response, "{}#osquery_fim".format(probe_source.get_absolute_url()))
        probe = response.context["probe"]
        self.assertEqual(len(probe.file_paths), 2)
        self.assertEqual(probe.file_paths[0].file_path, "48")
        self.assertEqual(probe.file_paths[1].file_path, "42")

    def test_delete_file_path_not_possible(self):
        self.log_user_in()
        _, probe_source, probe = self.create_probe(name="name", file_path="un")
        response = self.client.get(reverse("osquery:delete_fim_probe_file_path", args=(probe.pk, 0)))
        self.assertRedirects(response, "{}#osquery_fim".format(probe_source.get_absolute_url()))

    def test_delete_file_path_get_redirect(self):
        self.log_user_in()
        _, probe, _ = self.create_osquery_probe_with_extra_file_path("42")
        self.log_user_out()
        self.login_redirect(reverse("osquery:delete_fim_probe_file_path", args=(probe.pk, 0)))

    def test_delete_file_path_get(self):
        self.log_user_in()
        response, probe, probe_source = self.create_osquery_probe_with_extra_file_path("42")
        response = self.client.get(reverse("osquery:delete_fim_probe_file_path", args=(probe.pk, 0)))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Delete osquery fim probe file path")

    def test_delete_file_path_post_redirect(self):
        self.log_user_in()
        response, probe, probe_source = self.create_osquery_probe_with_extra_file_path("42")
        self.log_user_out()
        url = reverse("osquery:delete_fim_probe_file_path", args=(probe.pk, 1))
        response = self.client.post(url, follow=True)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def test_delete_file_path_post(self):
        self.log_user_in()
        response, probe, probe_source = self.create_osquery_probe_with_extra_file_path("42")
        response = self.client.post(reverse("osquery:delete_fim_probe_file_path", args=(probe.pk, 1)),
                                    follow=True)
        self.assertRedirects(response, "{}#osquery_fim".format(probe_source.get_absolute_url()))
        probe = response.context["probe"]
        self.assertEqual(len(probe.file_paths), 1)
        self.assertEqual(probe.file_paths[0].file_path, "un")

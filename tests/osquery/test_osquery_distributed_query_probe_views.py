from django.urls import reverse
from django.test import TestCase, override_settings
from zentral.core.probes.models import ProbeSource
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class OsqueryDistributedQueryProbeViewsTestCase(TestCase):
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
        self.login_redirect(reverse("osquery:create_distributed_query_probe"))

    def test_create_probe_get(self):
        self.log_user_in()
        response = self.client.get(reverse("osquery:create_distributed_query_probe"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/probes/form.html")
        self.assertContains(response, "Create osquery distributed query probe")

    def test_create_probe_error(self):
        self.log_user_in()
        response = self.client.post(reverse("osquery:create_distributed_query_probe"), {})
        self.assertFormError(response, "form", "query", "This field is required.")

    def test_create_probe_post_redirect(self):
        url = reverse("osquery:create_distributed_query_probe")
        response = self.client.post(url, {"name": "god", "query": "select 1;"}, follow=True)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def create_probe(self, **kwargs):
        self.log_user_in()
        response = self.client.post(reverse("osquery:create_distributed_query_probe"),
                                    kwargs,
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/distributed_query_probe.html")
        self.assertIn("probe", response.context)
        probe = response.context["probe"]
        self.assertIn("object", response.context)
        probe_source = response.context["object"]
        return response, probe_source, probe

    def test_create_probe(self):
        self.log_user_in()
        name = "godzilla auch"
        query = "select 1;"
        response, probe_source, probe = self.create_probe(name=name, query=query)
        self.assertEqual(probe.get_model(), "OsqueryDistributedQueryProbe")
        self.assertEqual(probe.name, name)
        self.assertEqual(probe.distributed_query, query)
        self.assertEqual(probe_source.name, name)
        self.assertEqual(probe_source.pk, probe.pk)
        self.assertContains(response, name)
        self.assertContains(response, '<span class="k">SELECT</span> '
                                      '<span class="mi">1</span><span class="p">;</span>')

    def test_update_probe_redirect(self):
        self.log_user_in()
        name = "godzilla auch"
        query = "select 1;"
        response, probe_source, probe = self.create_probe(name=name, query=query)
        self.log_user_out()
        url = reverse("osquery:update_distributed_query_probe_query", args=(probe.pk,))
        response = self.client.post(url, {"query": "select 2;"}, follow=True)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def test_update_probe(self):
        self.log_user_in()
        name = "godzilla auch"
        query = "select 1;"
        response, probe_source, probe = self.create_probe(name=name, query=query)
        response = self.client.post(reverse("osquery:update_distributed_query_probe_query", args=(probe.pk,)),
                                    {"query": "select 2;"},
                                    follow=True)
        self.assertRedirects(response, "{}#osquery".format(probe_source.get_absolute_url()))
        probe = response.context["probe"]
        self.assertEqual(probe.distributed_query, "select 2;")
        self.assertContains(response, '<span class="k">SELECT</span> '
                                      '<span class="mi">2</span><span class="p">;</span>')

    def test_index(self):
        self.log_user_in()
        name = "godzilla auch"
        query = "select 1;"
        response, probe_source, probe = self.create_probe(name=name, query=query)
        response = self.client.get(reverse("probes:index"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, name)
        probe_source.status = ProbeSource.ACTIVE
        probe_source.save()
        response = self.client.get(reverse("probes:index"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, name)

from django.core.urlresolvers import reverse
from django.test import TestCase, override_settings
from zentral.core.probes.models import ProbeSource


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class OsqueryProbeViewsTestCase(TestCase):
    def test_create_probe_get(self):
        response = self.client.get(reverse("osquery:create_probe"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/probes/form.html")
        self.assertContains(response, "Create osquery probe")

    def test_create_probe_error(self):
        response = self.client.post(reverse("osquery:create_probe"), {})
        self.assertFormError(response, "form", "interval", "This field is required.")
        self.assertFormError(response, "form", "query", "This field is required.")

    def create_probe(self, **kwargs):
        response = self.client.post(reverse("osquery:create_probe"),
                                    kwargs,
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/probe.html")
        self.assertIn("probe", response.context)
        probe = response.context["probe"]
        self.assertIn("object", response.context)
        probe_source = response.context["object"]
        return response, probe_source, probe

    def test_create_probe(self):
        name = "234390824"
        query = "select 2 from users;"
        response, probe_source, probe = self.create_probe(name=name, query=query, interval=1234)
        self.assertEqual(probe.get_model(), "OsqueryProbe")
        self.assertEqual(probe.name, name)
        self.assertEqual(probe.queries[0].query, query)
        self.assertEqual(probe_source.name, name)
        self.assertEqual(probe_source.pk, probe.pk)
        self.assertNotContains(response, reverse("osquery:delete_probe_query", args=(probe.pk, 0)))

    def test_index(self):
        name = "2343908241"
        query = "select 3 from users;"
        _, probe_source, probe = self.create_probe(name=name, query=query, interval=1234)
        response = self.client.get(reverse("probes:index"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, name)
        probe_source.status = ProbeSource.ACTIVE
        probe_source.save()
        response = self.client.get(reverse("probes:index"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, name)

    # queries

    def test_add_query_get(self):
        _, _, probe = self.create_probe(name="name", query="query", interval=42)
        response = self.client.get(reverse("osquery:add_probe_query", args=(probe.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/query_form.html")
        self.assertContains(response, "Add osquery query")

    def test_add_query_error(self):
        _, _, probe = self.create_probe(name="name", query="query", interval=42)
        response = self.client.post(reverse("osquery:add_probe_query", args=(probe.pk,)), {})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, "form", "interval", "This field is required.")
        self.assertFormError(response, "form", "query", "This field is required.")

    def create_osquery_probe_with_extra_query(self, query, interval):
        _, probe_source, probe = self.create_probe(name="name", query="query", interval=42)
        response = self.client.post(reverse("osquery:add_probe_query", args=(probe.pk,)),
                                    {"query": query, "interval": interval},
                                    follow=True)
        self.assertRedirects(response, "{}#osquery".format(probe_source.get_absolute_url()))
        return response, response.context["probe"], probe_source

    def test_add_query(self):
        response, probe, probe_source = self.create_osquery_probe_with_extra_query("select '42';", 34)
        self.assertEqual(len(probe.queries), 2)
        self.assertEqual(probe.queries[1].query, "select '42';")
        self.assertEqual(probe.queries[1].interval, 34)
        self.assertContains(response, reverse("osquery:delete_probe_query", args=(probe.pk, 0)))

    def test_edit_query_get(self):
        response, probe, probe_source = self.create_osquery_probe_with_extra_query("select '42';", 34)
        self.assertContains(response, reverse("osquery:update_probe_query", args=(probe.pk, 0)))
        self.assertContains(response, reverse("osquery:update_probe_query", args=(probe.pk, 1)))
        response = self.client.get(reverse("osquery:update_probe_query", args=(probe.pk, 0)))
        self.assertContains(response, "Update osquery query")

    def test_edit_query(self):
        response, probe, probe_source = self.create_osquery_probe_with_extra_query("select '42';", 34)
        updated_query = "select '32';"
        response = self.client.post(reverse("osquery:update_probe_query", args=(probe.pk, 0)),
                                    {"query": updated_query, "interval": 34},
                                    follow=True)
        self.assertRedirects(response, "{}#osquery".format(probe_source.get_absolute_url()))
        probe = response.context["probe"]
        self.assertEqual(len(probe.queries), 2)
        self.assertEqual(probe.queries[0].query, updated_query)
        self.assertEqual(probe.queries[1].query, "select '42';")

    def test_delete_query_not_possible(self):
        _, probe_source, probe = self.create_probe(name="name", query="query", interval=42)
        response = self.client.get(reverse("osquery:delete_probe_query", args=(probe.pk, 0)))
        self.assertRedirects(response, "{}#osquery".format(probe_source.get_absolute_url()))

    def test_delete_query_get(self):
        response, probe, probe_source = self.create_osquery_probe_with_extra_query("select '42';", 34)
        response = self.client.get(reverse("osquery:delete_probe_query", args=(probe.pk, 0)))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Delete osquery query")

    def test_delete_query_post(self):
        response, probe, probe_source = self.create_osquery_probe_with_extra_query("select '42';", 34)
        response = self.client.post(reverse("osquery:delete_probe_query", args=(probe.pk, 1)),
                                    follow=True)
        self.assertRedirects(response, "{}#osquery".format(probe_source.get_absolute_url()))
        probe = response.context["probe"]
        self.assertEqual(len(probe.queries), 1)
        self.assertEqual(probe.queries[0].query, "query")

    # dicovery

    def test_add_discovery_get(self):
        _, _, probe = self.create_probe(name="name", query="query", interval=42)
        response = self.client.get(reverse("osquery:add_probe_discovery", args=(probe.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/discovery_form.html")
        self.assertContains(response, "Add osquery discovery")

    def test_add_discovery_error(self):
        _, _, probe = self.create_probe(name="name", query="query", interval=42)
        response = self.client.post(reverse("osquery:add_probe_discovery", args=(probe.pk,)), {})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, "form", "query", "This field is required.")

    def create_osquery_probe_with_discovery(self, discovery):
        _, probe_source, probe = self.create_probe(name="name", query="query", interval=42)
        response = self.client.post(reverse("osquery:add_probe_discovery", args=(probe.pk,)),
                                    {"query": discovery},
                                    follow=True)
        self.assertRedirects(response, "{}#osquery".format(probe_source.get_absolute_url()))
        return response, response.context["probe"], probe_source

    def test_add_discovery(self):
        response, probe, probe_source = self.create_osquery_probe_with_discovery("new discovery")
        self.assertEqual(len(probe.discovery), 1)
        self.assertEqual(probe.discovery[0], "new discovery")
        self.assertContains(response, reverse("osquery:delete_probe_discovery", args=(probe.pk, 0)))

    def test_edit_discovery_get(self):
        response, probe, probe_source = self.create_osquery_probe_with_discovery("new discovery")
        response = self.client.get(reverse("osquery:update_probe_discovery", args=(probe.pk, 0)))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Update osquery discovery")

    def test_edit_discovery(self):
        response, probe, probe_source = self.create_osquery_probe_with_discovery("new discovery")
        response = self.client.post(reverse("osquery:update_probe_discovery", args=(probe.pk, 0)),
                                    {"query": "updated discovery"},
                                    follow=True)
        self.assertRedirects(response, "{}#osquery".format(probe_source.get_absolute_url()))
        probe = response.context["probe"]
        self.assertEqual(len(probe.discovery), 1)
        self.assertEqual(probe.discovery[0], "updated discovery")

    def test_delete_discovery_not_possible(self):
        _, probe_source, probe = self.create_probe(name="name", query="query", interval=42)
        response = self.client.get(reverse("osquery:delete_probe_discovery", args=(probe.pk, 0)))
        self.assertRedirects(response, "{}#osquery".format(probe_source.get_absolute_url()))

    def test_delete_discovery_get(self):
        response, probe, probe_source = self.create_osquery_probe_with_discovery("new discovery")
        response = self.client.get(reverse("osquery:delete_probe_discovery", args=(probe.pk, 0)))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Delete osquery discovery")

    def test_delete_discovery_post(self):
        response, probe, probe_source = self.create_osquery_probe_with_discovery("new discovery")
        response = self.client.post(reverse("osquery:delete_probe_discovery", args=(probe.pk, 0)),
                                    follow=True)
        self.assertRedirects(response, "{}#osquery".format(probe_source.get_absolute_url()))
        probe = response.context["probe"]
        self.assertEqual(len(probe.discovery), 0)

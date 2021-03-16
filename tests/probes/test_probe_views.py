from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from zentral.core.probes.models import ProbeSource
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class ProbeViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string())
        cls.group = Group.objects.create(name=get_random_string())
        cls.user.groups.set([cls.group])

    # utility methods

    def _login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def _login(self, *permissions):
        if permissions:
            permission_filter = reduce(operator.or_, (
                Q(content_type__app_label=app_label, codename=codename)
                for app_label, codename in (
                    permission.split(".")
                    for permission in permissions
                )
            ))
            self.group.permissions.set(list(Permission.objects.filter(permission_filter)))
        else:
            self.group.permissions.clear()
        self.client.force_login(self.user)

    def _force_probe(self, event_types=None, active=True):
        if event_types is None:
            event_types = ["zentral_login", "zentral_logout"]
        return ProbeSource.objects.create(
            model="BaseProbe",
            name=get_random_string(),
            status=ProbeSource.ACTIVE if active else ProbeSource.INACTIVE,
            body={"filters": {"metadata": [{"event_types": event_types}]}}
        )

    # create probe

    def test_create_probe_redirect(self):
        self._login_redirect(reverse("probes:create"))

    def test_create_probe_permission_denied(self):
        self._login()
        response = self.client.get(reverse("probes:create"))
        self.assertEqual(response.status_code, 403)

    def test_create_probe_get(self):
        self._login("probes.add_probesource")
        response = self.client.get(reverse("probes:create"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/probes/form.html")
        self.assertContains(response, "Create event probe")

    def test_create_probe_error(self):
        self._login("probes.add_probesource")
        response = self.client.post(reverse("probes:create"), {})
        self.assertFormError(response, "form", "name", "This field is required.")

    def test_create_probe(self, **kwargs):
        name = get_random_string()
        self._login("probes.add_probesource", "probes.view_probesource")
        response = self.client.post(reverse("probes:create"),
                                    {"name": name,
                                     "event_types": ["zentral_login",
                                                     "zentral_logout"]},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/probes/probe.html")
        self.assertIn("probe", response.context)
        probe = response.context["probe"]
        self.assertIn("object", response.context)
        probe_source = response.context["object"]
        self.assertEqual(probe.get_model(), "BaseProbe")
        self.assertEqual(probe.name, name)
        self.assertEqual(probe_source.name, name)
        self.assertEqual(probe_source.pk, probe.pk)

    # index

    def test_index_redirect(self):
        self._login_redirect(reverse("probes:index"))

    def test_index_permission_denied(self):
        self._login()
        response = self.client.get(reverse("probes:index"))
        self.assertEqual(response.status_code, 403)

    def test_index_no_inactive(self):
        probe_source = self._force_probe(active=False)
        probe_source2 = self._force_probe()
        self._login("probes.view_probesource")
        response = self.client.get(reverse("probes:index"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, probe_source.name)
        self.assertContains(response, probe_source2.name)

    # dashboard

    def test_dashboard_redirect(self):
        probe_source = self._force_probe()
        self._login_redirect(reverse("probes:probe_dashboard", args=(probe_source.pk,)))

    def test_dashboard_permission_denied(self):
        probe_source = self._force_probe()
        self._login()
        response = self.client.get(reverse("probes:probe_dashboard", args=(probe_source.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_dashboard_multi_event_types(self):
        probe_source = self._force_probe(event_types=["zentral_login", "zentral_logout"])
        self._login("probes.view_probesource")
        response = self.client.get(reverse("probes:probe_dashboard", args=(probe_source.pk,)))
        self.assertContains(response, "Events")
        self.assertContains(response, "Event types")

    def test_dashboard_single_event_type(self):
        probe_source = self._force_probe(event_types=["zentral_login"])
        self._login("probes.view_probesource")
        response = self.client.get(reverse("probes:probe_dashboard", args=(probe_source.pk,)))
        self.assertContains(response, "Events")
        self.assertNotContains(response, "Event types")

    # dashboard data

    def test_dashboard_data_redirect(self):
        probe_source = self._force_probe()
        self._login_redirect(reverse("probes:probe_dashboard_data", args=(probe_source.pk,)))

    def test_dashboard_data_permission_denied(self):
        probe_source = self._force_probe()
        self._login()
        response = self.client.get(reverse("probes:probe_dashboard_data", args=(probe_source.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_dashboard_data_multi_event_types(self):
        probe_source = self._force_probe(event_types=["zentral_login", "zentral_logout"])
        self._login("probes.view_probesource")
        response = self.client.get(reverse("probes:probe_dashboard_data", args=(probe_source.pk,)))
        self.assertEqual(response["Content-Type"], "application/json")
        data = response.json()
        self.assertCountEqual(data, ["event_type", "created_at"])

    def test_dashboard_data_single_event_types(self):
        probe_source = self._force_probe(event_types=["zentral_login"])
        self._login("probes.view_probesource")
        response = self.client.get(reverse("probes:probe_dashboard_data", args=(probe_source.pk,)))
        self.assertEqual(response["Content-Type"], "application/json")
        data = response.json()
        self.assertCountEqual(data, ["created_at"])

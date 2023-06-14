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
class MunkiInstallProbeViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.pwd = "godzillapwd"
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", cls.pwd)
        cls.group = Group.objects.create(name=get_random_string(12))
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

    def _force_probe(self, active=False):
        return ProbeSource.objects.create(
            model="MunkiInstallProbe",
            name=get_random_string(12),
            status=ProbeSource.ACTIVE if active else ProbeSource.INACTIVE,
            body={'install_types': ['removal'], 'unattended_installs': False},
        )

    # create probe

    def test_create_probe_redirect(self):
        self._login_redirect(reverse("munki:create_install_probe"))

    def test_create_probe_permission_denied(self):
        self._login()
        response = self.client.get(reverse("munki:create_install_probe"))
        self.assertEqual(response.status_code, 403)

    def test_create_probe_get(self):
        self._login("probes.add_probesource")
        response = self.client.get(reverse("munki:create_install_probe"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/form.html")
        self.assertContains(response, "Create munki install probe")

    def test_create_probe_post_error(self):
        self._login("probes.add_probesource")
        response = self.client.post(reverse("munki:create_install_probe"), {})
        self.assertTemplateUsed(response, "probes/form.html")
        self.assertFormError(response.context["form"], "install_types", "This field is required.")

    def test_create_probe_post_redirect(self):
        url = reverse("munki:create_install_probe")
        response = self.client.post(url, {"name": "io", "install_types": "removal"}, follow=True)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def test_create_probe_post_permission_denied(self):
        url = reverse("munki:create_install_probe")
        self._login()
        response = self.client.post(url, {"name": "io", "install_types": "removal"}, follow=True)
        self.assertEqual(response.status_code, 403)

    def test_create_probe_post_ok(self):
        name = "munki godz"
        install_types = "removal"
        unattended_installs = '0'
        self._login("probes.add_probesource", "probes.view_probesource")
        response = self.client.post(reverse("munki:create_install_probe"),
                                    {"name": name,
                                     "install_types": install_types,
                                     "unattended_installs": unattended_installs},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/install_probe.html")
        self.assertIn("probe", response.context)
        probe = response.context["probe"]
        self.assertEqual(probe.get_model(), "MunkiInstallProbe")
        self.assertEqual(probe.name, name)
        self.assertEqual(probe.unattended_installs, False)
        self.assertEqual(probe.install_types, set([install_types]))
        self.assertIn("object", response.context)
        probe_source = response.context["object"]
        self.assertEqual(probe_source.name, name)
        self.assertEqual(probe_source.pk, probe.pk)
        self.assertContains(response, name)
        self.assertContains(response, install_types)

    # update probe

    def test_update_probe_redirect(self):
        probe_source = self._force_probe()
        self._login_redirect(reverse("munki:update_install_probe", args=(probe_source.pk,)))

    def test_update_probe_permission_denied(self):
        probe_source = self._force_probe()
        self._login()
        response = self.client.get(reverse("munki:update_install_probe", args=(probe_source.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_probe_get(self):
        probe_source = self._force_probe()
        self._login("probes.change_probesource")
        response = self.client.get(reverse("munki:update_install_probe", args=(probe_source.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/form.html")

    def test_update_probe_post(self):
        probe_source = self._force_probe()
        self._login("probes.change_probesource", "probes.view_probesource")
        response = self.client.post(reverse("munki:update_install_probe", args=(probe_source.pk,)),
                                    {"install_types": "install,removal"},
                                    follow=True)
        self.assertRedirects(response, "{}#munki".format(probe_source.get_absolute_url()))
        probe = response.context["probe"]
        self.assertEqual(probe.install_types, set(["install", "removal"]))
        self.assertContains(response, "install, removal")

    # probes index

    def test_index(self):
        probe_source = self._force_probe(active=True)
        self._login("probes.view_probesource")
        response = self.client.get(reverse("probes:index"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, probe_source.name)

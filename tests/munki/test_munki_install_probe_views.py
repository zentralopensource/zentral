from django.core.urlresolvers import reverse
from django.test import TestCase, override_settings
from zentral.core.probes.models import ProbeSource


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MunkiInstallProbeViewsTestCase(TestCase):
    def test_create_probe_get(self):
        response = self.client.get(reverse("munki:create_install_probe"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/probes/form.html")
        self.assertContains(response, "Create munki install probe")

    def test_create_probe_error(self):
        response = self.client.post(reverse("munki:create_install_probe"), {})
        self.assertFormError(response, "form", "install_types", "This field is required.")

    def create_probe(self, **kwargs):
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
        name = "munki godz"
        install_types = "removal"
        unattended_installs = '0'
        response, probe_source, probe = self.create_probe(name=name,
                                                          install_types=install_types,
                                                          unattended_installs=unattended_installs)
        response = self.client.post(reverse("munki:update_install_probe", args=(probe.pk,)),
                                    {"install_types": "install,removal"},
                                    follow=True)
        self.assertRedirects(response, "{}#munki".format(probe_source.get_absolute_url()))
        probe = response.context["probe"]
        self.assertEqual(probe.install_types, set(["install", "removal"]))
        self.assertContains(response, "install, removal")

    def test_index(self):
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

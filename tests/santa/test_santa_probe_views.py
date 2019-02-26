from django.urls import reverse
from django.test import TestCase, override_settings
from zentral.core.probes.models import ProbeSource
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class SantaProbeViewsTestCase(TestCase):
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
        url = reverse("santa:create_probe")
        self.login_redirect(url)
        self.log_user_in()
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/create_probe.html")
        self.assertContains(response, "Create santa probe")

    def test_create_probe_error(self):
        self.log_user_in()
        response = self.client.post(reverse("santa:create_probe"), {})
        self.assertFormError(response, "form", "name", "This field is required.")

    def test_create_probe_post_redirect(self):
        url = reverse("santa:create_probe")
        response = self.client.post(url, {"name": "234390824",
                                          "policy": "BLACKLIST",
                                          "rule_type": "BINARY",
                                          "sha256": 64*"a"}, follow=True)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def create_probe(self, **kwargs):
        self.log_user_in()
        response = self.client.post(reverse("santa:create_probe"),
                                    kwargs, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/probe.html")
        self.assertIn("probe", response.context)
        probe = response.context["probe"]
        self.assertIn("object", response.context)
        probe_source = response.context["object"]
        return response, probe_source, probe

    def test_create_probe(self):
        self.log_user_in()
        kwargs = {"name": "234390824",
                  "policy": "BLACKLIST",
                  "rule_type": "BINARY",
                  "sha256": 64*"a"}
        response, probe_source, probe = self.create_probe(**kwargs)
        self.assertEqual(probe.get_model(), "SantaProbe")
        self.assertEqual(probe.name, kwargs["name"])
        self.assertEqual(probe.rules[0].sha256, kwargs["sha256"])
        self.assertEqual(probe_source.name, kwargs["name"])
        self.assertEqual(probe_source.pk, probe.pk)
        self.assertNotContains(response, reverse("santa:delete_probe_rule", args=(probe.pk, 0)))

    def test_index(self):
        self.log_user_in()
        kwargs = {"name": "234390824",
                  "policy": "BLACKLIST",
                  "rule_type": "BINARY",
                  "sha256": 64*"a"}
        _, probe_source, probe = self.create_probe(**kwargs)
        response = self.client.get(reverse("probes:index"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, kwargs["name"])
        probe_source.status = ProbeSource.ACTIVE
        probe_source.save()
        response = self.client.get(reverse("probes:index"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, kwargs["name"])

    # rules

    def test_add_rule_get(self):
        self.log_user_in()
        kwargs = {"name": "ui",
                  "policy": "BLACKLIST",
                  "rule_type": "BINARY",
                  "sha256": 64*"a"}
        _, _, probe = self.create_probe(**kwargs)
        url = reverse("santa:add_probe_rule", args=(probe.pk,))
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/rule_form.html")
        self.assertContains(response, "Add santa rule")
        self.log_user_out()
        self.login_redirect(url)

    def test_add_rule_error(self):
        self.log_user_in()
        kwargs = {"name": "234390824",
                  "policy": "BLACKLIST",
                  "rule_type": "BINARY",
                  "sha256": 64*"a"}
        _, _, probe = self.create_probe(**kwargs)
        response = self.client.post(reverse("santa:add_probe_rule", args=(probe.pk,)), {})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, "form", "rule_type", "This field is required.")

    def create_santa_probe_with_extra_rule(self, **kwargs):
        self.log_user_in()
        _, probe_source, probe = self.create_probe(**kwargs)
        del kwargs["name"]
        kwargs["sha256"] = 64 * "b"
        response = self.client.post(reverse("santa:add_probe_rule", args=(probe.pk,)),
                                    kwargs,
                                    follow=True)
        self.assertRedirects(response, "{}#santa".format(probe_source.get_absolute_url()))
        return response, response.context["probe"], probe_source

    def test_add_rule_post(self):
        self.log_user_in()
        kwargs = {"name": "234390824",
                  "policy": "BLACKLIST",
                  "rule_type": "BINARY",
                  "sha256": 64*"a"}
        response, probe, probe_source = self.create_santa_probe_with_extra_rule(**kwargs)
        self.assertEqual(len(probe.rules), 2)
        self.assertEqual(probe.rules[0].sha256, 64 * "a")
        self.assertEqual(probe.rules[1].sha256, 64 * "b")
        self.assertContains(response, reverse("santa:delete_probe_rule", args=(probe.pk, 0)))

    def test_update_rule_get(self):
        self.log_user_in()
        kwargs = {"name": "234390824",
                  "policy": "BLACKLIST",
                  "rule_type": "BINARY",
                  "sha256": 64*"a"}
        response, probe, probe_source = self.create_santa_probe_with_extra_rule(**kwargs)
        url = reverse("santa:update_probe_rule", args=(probe.pk, 0))
        self.assertContains(response, url)
        self.assertContains(response, reverse("santa:update_probe_rule", args=(probe.pk, 1)))
        response = self.client.get(url)
        self.assertContains(response, "Update santa rule")
        self.log_user_out()
        self.login_redirect(url)

    def test_update_rule_post(self):
        self.log_user_in()
        kwargs = {"name": "234390824",
                  "policy": "BLACKLIST",
                  "rule_type": "BINARY",
                  "sha256": 64*"a"}
        response, probe, probe_source = self.create_santa_probe_with_extra_rule(**kwargs)
        kwargs["sha256"] = 64 * "c"
        response = self.client.post(reverse("santa:update_probe_rule", args=(probe.pk, 0)),
                                    kwargs, follow=True)
        self.assertRedirects(response, "{}#santa".format(probe_source.get_absolute_url()))
        probe = response.context["probe"]
        self.assertEqual(len(probe.rules), 2)
        self.assertEqual(probe.rules[0].sha256, 64 * "c")
        self.assertEqual(probe.rules[1].sha256, 64 * "b")

    def test_delete_rule_not_possible(self):
        self.log_user_in()
        kwargs = {"name": "234390824",
                  "policy": "BLACKLIST",
                  "rule_type": "BINARY",
                  "sha256": 64*"a"}
        _, probe_source, probe = self.create_probe(**kwargs)
        response = self.client.get(reverse("santa:delete_probe_rule", args=(probe.pk, 0)))
        self.assertRedirects(response, "{}#santa".format(probe_source.get_absolute_url()))

    def test_delete_rule_get(self):
        self.log_user_in()
        kwargs = {"name": "ZU",
                  "policy": "BLACKLIST",
                  "rule_type": "BINARY",
                  "sha256": 64*"a"}
        response, probe, probe_source = self.create_santa_probe_with_extra_rule(**kwargs)
        url = reverse("santa:delete_probe_rule", args=(probe.pk, 0))
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Delete santa rule")
        self.log_user_out()
        self.login_redirect(url)

    def test_delete_rule_post_redirect(self):
        self.log_user_in()
        kwargs = {"name": "UI",
                  "policy": "BLACKLIST",
                  "rule_type": "BINARY",
                  "sha256": 64*"a"}
        response, probe, probe_source = self.create_santa_probe_with_extra_rule(**kwargs)
        self.log_user_out()
        url = reverse("santa:delete_probe_rule", args=(probe.pk, 1))
        response = self.client.post(url, follow=True)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))
        self.log_user_in()
        response = self.client.post(url, follow=True)
        self.assertRedirects(response, "{}#santa".format(probe_source.get_absolute_url()))
        probe = response.context["probe"]
        self.assertEqual(len(probe.rules), 1)
        self.assertEqual(probe.rules[0].sha256, 64 * "a")

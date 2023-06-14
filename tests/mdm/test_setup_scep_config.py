from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.mdm.models import UserEnrollment, PushCertificate, SCEPConfig


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MDMUserEnrollmentSetupViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()

    # utiliy methods

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

    def _force_push_certificate(self):
        push_certificate = PushCertificate(
            name=get_random_string(12),
            topic=get_random_string(12),
            not_before="2000-01-01",
            not_after="2040-01-01",
            certificate=b"1",
        )
        push_certificate.set_private_key(b"2")
        push_certificate.save()
        return push_certificate

    def _force_scep_config(self):
        scep_config = SCEPConfig(
            name=get_random_string(12),
            url="https://example.com/{}".format(get_random_string(12)),
            challenge_type="STATIC",
        )
        scep_config.set_challenge_kwargs({"challenge": get_random_string(12)})
        scep_config.save()
        return scep_config

    def _force_user_enrollment(self):
        return UserEnrollment.objects.create(
            push_certificate=self._force_push_certificate(),
            scep_config=self._force_scep_config(),
            name=get_random_string(12),
            enrollment_secret=EnrollmentSecret.objects.create(meta_business_unit=self.mbu)
        )

    # rewrap challenge

    def test_rewrap_secrets(self):
        scep_config = self._force_scep_config()
        challenge_kwargs = scep_config.get_challenge_kwargs()
        self.assertIsNotNone(challenge_kwargs)
        scep_config.rewrap_secrets()
        self.assertEqual(scep_config.get_challenge_kwargs(), challenge_kwargs)

    # create SCEP config

    def test_create_scep_config_redirect(self):
        self._login_redirect(reverse("mdm:create_scep_config"))

    def test_create_scep_config_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:create_scep_config"))
        self.assertEqual(response.status_code, 403)

    def test_create_scep_config_get(self):
        self._login("mdm.add_scepconfig")
        response = self.client.get(reverse("mdm:create_scep_config"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/scepconfig_form.html")
        self.assertContains(response, "Create SCEP configuration")

    def test_create_scep_config_static_post(self):
        self._login("mdm.add_scepconfig", "mdm.view_scepconfig")
        name = get_random_string(64)
        url = "https://example.com/{}".format(get_random_string(12))
        challenge = get_random_string(12)
        response = self.client.post(reverse("mdm:create_scep_config"),
                                    {"sc-name": name,
                                     "sc-url": url,
                                     "sc-key_usage": 0,
                                     "sc-key_is_extractable": "on",
                                     "sc-keysize": 2048,
                                     "sc-allow_all_apps_access": "on",
                                     "sc-challenge_type": "STATIC",
                                     "s-challenge": challenge},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/scepconfig_detail.html")
        self.assertContains(response, name)
        self.assertContains(response, url)
        self.assertContains(response, challenge)
        scep_config = response.context["object"]
        self.assertEqual(scep_config.name, name)
        self.assertEqual(scep_config.url, url)
        self.assertEqual(scep_config.get_challenge_kwargs()["challenge"], challenge)

    # view SCEP config

    def test_view_scep_config_redirect(self):
        scep_config = self._force_scep_config()
        self._login_redirect(reverse("mdm:scep_config", args=(scep_config.pk,)))

    def test_view_scep_config_permission_denied(self):
        scep_config = self._force_scep_config()
        self._login()
        response = self.client.get(reverse("mdm:scep_config", args=(scep_config.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_view_scep_config(self):
        scep_config = self._force_scep_config()
        self._login("mdm.view_scepconfig", "mdm.delete_scepconfig")
        response = self.client.get(reverse("mdm:scep_config", args=(scep_config.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/scepconfig_detail.html")
        self.assertContains(response, scep_config.name)
        self.assertContains(response, scep_config.url)
        self.assertContains(response, scep_config.get_challenge_kwargs()["challenge"])
        self.assertContains(response, reverse("mdm:delete_scep_config", args=(scep_config.pk,)))

    def test_no_delete_scep_config_link(self):
        enrollment = self._force_user_enrollment()
        self._login("mdm.view_scepconfig", "mdm.delete_scepconfig")
        response = self.client.get(reverse("mdm:scep_config", args=(enrollment.scep_config.pk,)))
        self.assertNotContains(response, reverse("mdm:delete_scep_config", args=(enrollment.scep_config.pk,)))

    # update SCEP config

    def test_update_scep_config_redirect(self):
        scep_config = self._force_scep_config()
        self._login_redirect(reverse("mdm:update_scep_config", args=(scep_config.pk,)))

    def test_update_scep_config_permission_denied(self):
        scep_config = self._force_scep_config()
        self._login()
        response = self.client.get(reverse("mdm:update_scep_config", args=(scep_config.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_scep_config_get(self):
        scep_config = self._force_scep_config()
        self._login("mdm.change_scepconfig")
        response = self.client.get(reverse("mdm:update_scep_config", args=(scep_config.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/scepconfig_form.html")
        self.assertContains(response, f"Update {scep_config.name}")

    def test_update_scep_config_microsoft_ca_post(self):
        scep_config = self._force_scep_config()
        self._login("mdm.change_scepconfig", "mdm.view_scepconfig")
        new_name = get_random_string(12)
        mc_url = "https://example.com/{}".format(get_random_string(12))
        mc_username = get_random_string(12)
        mc_password = get_random_string(12)
        response = self.client.post(reverse("mdm:update_scep_config", args=(scep_config.pk,)),
                                    {"sc-name": new_name,
                                     "sc-url": scep_config.url,
                                     "sc-key_usage": scep_config.key_usage,
                                     "sc-key_is_extractable": "on" if scep_config.key_is_extractable else "",
                                     "sc-keysize": scep_config.keysize,
                                     "sc-allow_all_apps_access": "on" if scep_config.allow_all_apps_access else "",
                                     "sc-challenge_type": "MICROSOFT_CA",
                                     "mc-url": mc_url,
                                     "mc-username": mc_username,
                                     "mc-password": mc_password},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/scepconfig_detail.html")
        self.assertContains(response, new_name)
        self.assertContains(response, mc_url)
        self.assertContains(response, mc_username)
        self.assertContains(response, mc_password)
        scep_config = response.context["object"]
        scep_config_challenge_kwargs = scep_config.get_challenge_kwargs()
        self.assertEqual(scep_config_challenge_kwargs["url"], mc_url)
        self.assertEqual(scep_config_challenge_kwargs["username"], mc_username)
        self.assertEqual(scep_config_challenge_kwargs["password"], mc_password)

    # list SCEP configs

    def test_list_scep_configs_redirect(self):
        self._login_redirect(reverse("mdm:scep_configs"))

    def test_list_scep_configs_permission_denied(self):
        self._force_scep_config()
        self._login()
        response = self.client.get(reverse("mdm:scep_configs"))
        self.assertEqual(response.status_code, 403)

    def test_list_scep_configs(self):
        scep_config = self._force_scep_config()
        self._login("mdm.view_scepconfig")
        response = self.client.get(reverse("mdm:scep_configs"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/scepconfig_list.html")
        self.assertContains(response, "1 SCEP configuration")
        self.assertContains(response, scep_config.name)

    # delete SCEP config

    def test_delete_scep_config_redirect(self):
        scep_config = self._force_scep_config()
        self._login_redirect(reverse("mdm:delete_scep_config", args=(scep_config.pk,)))

    def test_delete_scep_config_permission_denied(self):
        scep_config = self._force_scep_config()
        self._login()
        response = self.client.get(reverse("mdm:delete_scep_config", args=(scep_config.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_scep_config_get(self):
        scep_config = self._force_scep_config()
        self._login("mdm.delete_scepconfig")
        response = self.client.get(reverse("mdm:delete_scep_config", args=(scep_config.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/scepconfig_confirm_delete.html")
        self.assertContains(response, f"Delete {scep_config.name}")

    def test_delete_scep_config_post(self):
        scep_config = self._force_scep_config()
        self._login("mdm.delete_scepconfig", "mdm.view_scepconfig")
        response = self.client.post(reverse("mdm:delete_scep_config", args=(scep_config.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/scepconfig_list.html")
        self.assertContains(response, "0 SCEP configurations")

    def test_delete_scep_config_bad_request(self):
        enrollment = self._force_user_enrollment()
        self._login("mdm.delete_scepconfig")
        response = self.client.post(reverse("mdm:delete_scep_config", args=(enrollment.scep_config.pk,)), follow=True)
        self.assertEqual(response.status_code, 400)

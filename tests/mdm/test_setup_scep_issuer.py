from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.inventory.models import MetaBusinessUnit
from .utils import force_scep_issuer


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

    # can be deleted

    def test_no_provisioning_uid_can_be_deleted(self):
        scep_issuer = force_scep_issuer()
        self.assertTrue(scep_issuer.can_be_deleted())

    def test_provisioning_uid_cannot_be_deleted(self):
        scep_issuer = force_scep_issuer(provisioning_uid="yolo")
        self.assertFalse(scep_issuer.can_be_deleted())

    # can be updated

    def test_no_provisioning_uid_can_be_updated(self):
        scep_issuer = force_scep_issuer()
        self.assertTrue(scep_issuer.can_be_updated())

    def test_provisioning_uid_cannot_be_edited(self):
        scep_issuer = force_scep_issuer(provisioning_uid="yolo")
        self.assertFalse(scep_issuer.can_be_updated())

    # backend kwargs getter

    def test_dynamic_backend_kwargs_getter_missing_attr(self):
        scep_issuer = force_scep_issuer()
        with self.assertRaises(AttributeError):
            scep_issuer.yolo

    def test_dynamic_backend_kwargs_getter(self):
        scep_issuer = force_scep_issuer()
        self.assertEqual(scep_issuer.get_static_challenge_kwargs(), scep_issuer.get_backend_kwargs())
        self.assertIsNone(scep_issuer.get_microsoft_ca_kwargs())
        self.assertIsNone(scep_issuer.get_okta_ca_kwargs())

    # rewrap challenge

    def test_rewrap_secrets(self):
        scep_issuer = force_scep_issuer()
        backend_kwargs = scep_issuer.get_backend_kwargs()
        self.assertIsNotNone(backend_kwargs)
        scep_issuer.rewrap_secrets()
        self.assertEqual(scep_issuer.get_backend_kwargs(), backend_kwargs)

    # view SCEP issuer

    def test_view_scep_issuer_redirect(self):
        scep_issuer = force_scep_issuer()
        self._login_redirect(reverse("mdm:scep_issuer", args=(scep_issuer.pk,)))

    def test_view_scep_issuer_permission_denied(self):
        scep_issuer = force_scep_issuer()
        self._login()
        response = self.client.get(reverse("mdm:scep_issuer", args=(scep_issuer.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_view_scep_issuer(self):
        scep_issuer = force_scep_issuer()
        self._login("mdm.view_scepissuer", "mdm.delete_scepissuer", "mdm.change_scepissuer")
        response = self.client.get(reverse("mdm:scep_issuer", args=(scep_issuer.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/scepissuer_detail.html")
        self.assertContains(response, scep_issuer.name)
        self.assertContains(response, scep_issuer.url)
        self.assertContains(response, scep_issuer.get_backend_kwargs()["challenge"])

    def test_view_provisioned_scep_issuer(self):
        scep_issuer = force_scep_issuer(provisioning_uid=get_random_string(12))
        self._login("mdm.view_scepissuer", "mdm.delete_scepissuer", "mdm.change_scepissuer")
        response = self.client.get(reverse("mdm:scep_issuer", args=(scep_issuer.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/scepissuer_detail.html")
        self.assertContains(response, scep_issuer.name)
        self.assertContains(response, scep_issuer.url)
        self.assertNotContains(response, scep_issuer.get_backend_kwargs()["challenge"])

    # list SCEP issuers

    def test_list_scep_issuers_redirect(self):
        self._login_redirect(reverse("mdm:scep_issuers"))

    def test_list_scep_issuers_permission_denied(self):
        force_scep_issuer()
        self._login()
        response = self.client.get(reverse("mdm:scep_issuers"))
        self.assertEqual(response.status_code, 403)

    def test_list_scep_issuers(self):
        scep_issuer = force_scep_issuer()
        self._login("mdm.view_scepissuer")
        response = self.client.get(reverse("mdm:scep_issuers"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/scepissuer_list.html")
        self.assertContains(response, "SCEP issuer (1)")
        self.assertContains(response, scep_issuer.name)

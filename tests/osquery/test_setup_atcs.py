from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import User
from tests.zentral_test_utils.login_case import LoginCase
from zentral.contrib.osquery.models import AutomaticTableConstruction


class OsquerySetupATCViewsTestCase(TestCase, LoginCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "osquery"

    # utiliy methods

    def _get_atc_dict(self, **kwargs):
        d = {
            "name": get_random_string(12),
            "description": get_random_string(12),
            "table_name": get_random_string(length=12, allowed_chars="abcd_"),
            "query": "select 1 from yo;",
            "path": "/home/yolo",
            "columns": ["un", "deux"],
            "platforms": ["darwin", "windows"],
        }
        d.update(**kwargs)
        return d

    def _force_atc(self):
        atc_dict = self._get_atc_dict()
        return AutomaticTableConstruction.objects.create(**atc_dict), atc_dict

    # create atc

    def test_create_atc_redirect(self):
        self.login_redirect("create_atc")

    def test_create_atc_permission_denied(self):
        self.login()
        response = self.client.get(reverse("osquery:create_atc"))
        self.assertEqual(response.status_code, 403)

    def test_create_atc_get(self):
        self.login("osquery.add_automatictableconstruction")
        response = self.client.get(reverse("osquery:create_atc"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/automatictableconstruction_form.html")
        self.assertContains(response, "Create Automatic table construction")

    def test_create_atc_post(self):
        self.login("osquery.add_automatictableconstruction", "osquery.view_automatictableconstruction")
        atc_name = get_random_string(12)
        atc_description = get_random_string(12)
        atc_dict = self._get_atc_dict(name=atc_name, description=atc_description)
        response = self.client.post(reverse("osquery:create_atc"), atc_dict, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/automatictableconstruction_detail.html")
        self.assertContains(response, atc_name)
        atc = response.context["object"]
        self.assertEqual(atc.name, atc_name)
        self.assertEqual(atc.description, atc_description)

    # update atc

    def test_update_atc_redirect(self):
        atc, _ = self._force_atc()
        self.login_redirect("update_atc", atc.pk)

    def test_update_atc_permission_denied(self):
        atc, _ = self._force_atc()
        self.login()
        response = self.client.get(reverse("osquery:update_atc", args=(atc.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_atc_get(self):
        atc, _ = self._force_atc()
        self.login("osquery.change_automatictableconstruction")
        response = self.client.get(reverse("osquery:update_atc", args=(atc.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/automatictableconstruction_form.html")

    def test_update_atc_post(self):
        atc, atc_dict = self._force_atc()
        self.login("osquery.change_automatictableconstruction", "osquery.view_automatictableconstruction")
        atc_dict["name"] = get_random_string(12)
        response = self.client.post(reverse("osquery:update_atc", args=(atc.pk,)),
                                    atc_dict, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/automatictableconstruction_detail.html")
        self.assertContains(response, atc_dict["name"])
        atc = response.context["object"]
        self.assertEqual(atc.name, atc_dict["name"])

    # delete atc

    def test_delete_atc_redirect(self):
        atc, _ = self._force_atc()
        self.login_redirect("delete_atc", atc.pk)

    def test_delete_atc_permission_denied(self):
        atc, _ = self._force_atc()
        self.login()
        response = self.client.get(reverse("osquery:delete_atc", args=(atc.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_atc_get(self):
        atc, _ = self._force_atc()
        self.login("osquery.delete_automatictableconstruction")
        response = self.client.get(reverse("osquery:delete_atc", args=(atc.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/automatictableconstruction_confirm_delete.html")
        self.assertContains(response, atc.name)

    def test_delete_atc_post(self):
        atc, _ = self._force_atc()
        self.login("osquery.delete_automatictableconstruction", "osquery.view_automatictableconstruction")
        response = self.client.post(reverse("osquery:delete_atc", args=(atc.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/automatictableconstruction_list.html")
        self.assertEqual(AutomaticTableConstruction.objects.filter(pk=atc.pk).count(), 0)
        self.assertNotContains(response, atc.name)

    # atc list

    def test_atc_list_redirect(self):
        self.login_redirect("atcs")

    def test_atc_list_permission_denied(self):
        self.login()
        response = self.client.get(reverse("osquery:atcs"))
        self.assertEqual(response.status_code, 403)

    def test_atc_list(self):
        atc, _ = self._force_atc()
        self.login("osquery.view_automatictableconstruction")
        response = self.client.get(reverse("osquery:atcs"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/automatictableconstruction_list.html")
        self.assertIn(atc, response.context["object_list"])
        self.assertContains(response, atc.name)

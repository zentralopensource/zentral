from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import ProvisionedRole, User
from tests.zentral_test_utils.login_case import LoginCase


class AccountUsersViewsTestCase(TestCase, LoginCase):
    @classmethod
    def setUpTestData(cls):
        # ui user
        cls.ui_user = User.objects.create_user(get_random_string(12),
                                               "{}@zentral.io".format(get_random_string(12)),
                                               get_random_string(12),
                                               is_superuser=False)
        # ui group
        cls.ui_group = Group.objects.create(name=get_random_string(12))
        cls.ui_user.groups.set([cls.ui_group])
        # groups
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.provisioned_group = Group.objects.create(name=get_random_string(12))
        ProvisionedRole.objects.create(group=cls.provisioned_group, provisioning_uid=get_random_string(12))

    # LoginCase implementation

    def _get_user(self):
        return self.ui_user

    def _get_group(self):
        return self.ui_group

    def _get_url_namespace(self):
        return "accounts"

    # permissions denied

    def test_group_list_redirect(self):
        self.login_redirect("groups")
        self.login()
        self.permission_denied("groups")
        self.login("auth.change_group")
        self.permission_denied("groups")

    def test_create_group_redirect(self):
        self.login_redirect("create_group")
        self.login()
        self.permission_denied("create_group")
        self.login("auth.view_group")
        self.permission_denied("create_group")

    def test_group_update_redirect(self):
        self.login_redirect("update_group", self.group.pk)
        self.login()
        self.permission_denied("update_group", self.group.pk)
        self.login("auth.add_group")
        self.permission_denied("update_group", self.group.pk)

    def test_user_delete_redirect(self):
        self.login_redirect("delete_group", self.group.pk)
        self.login()
        self.permission_denied("delete_group", self.group.pk)
        self.login("accounts.add_user")
        self.permission_denied("delete_group", self.group.pk)

    # group list

    def test_group_list_ok(self):
        self.login("auth.view_group")
        response = self.client.get(reverse("accounts:groups"))
        self.assertTemplateUsed(response, "accounts/group_list.html")
        self.assertContains(response, self.group.name)
        self.assertContains(response, self.provisioned_group.name)
        for text in (reverse("accounts:delete_group", args=(self.group.pk,)),
                     reverse("accounts:update_group", args=(self.group.pk,)),
                     reverse("accounts:create_group")):
            self.assertNotContains(response, text)
        for text in (reverse("accounts:delete_group", args=(self.provisioned_group.pk,)),
                     reverse("accounts:update_group", args=(self.provisioned_group.pk,))):
            self.assertNotContains(response, text)
        self.login("auth.view_group", "auth.add_group", "auth.change_group", "auth.delete_group")
        response = self.client.get(reverse("accounts:groups"))
        for text in (reverse("accounts:delete_group", args=(self.group.pk,)),
                     reverse("accounts:update_group", args=(self.group.pk,)),
                     reverse("accounts:create_group")):
            self.assertContains(response, text)
        for text in (reverse("accounts:delete_group", args=(self.provisioned_group.pk,)),
                     reverse("accounts:update_group", args=(self.provisioned_group.pk,))):
            self.assertNotContains(response, text)

    # create group

    def test_create_group_get(self):
        self.login("auth.add_group")
        response = self.client.get(reverse("accounts:create_group"))
        self.assertTemplateUsed(response, "accounts/group_form.html")
        self.assertContains(response, "Roles")
        self.assertContains(response, "Create")

    def test_create_group_error(self):
        self.login("auth.add_group")
        response = self.client.post(reverse("accounts:create_group"),
                                    {"name": self.group.name},
                                    follow=True)
        self.assertFormError(response.context["form"], "name", "Group with this Name already exists.")

    def test_create_group_ok(self):
        self.login("auth.add_group", "auth.view_group")
        name = get_random_string(12)
        response = self.client.post(reverse("accounts:create_group"),
                                    {"name": name},
                                    follow=True)
        self.assertTemplateUsed("accounts/group_detail.html")
        self.assertContains(response, name)

    # view group

    def test_view_group_no_perms_get(self):
        self.login("auth.view_group")
        response = self.client.get(reverse("accounts:group", args=(self.group.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/group_detail.html")
        self.assertContains(response, self.group.name)
        for text in (reverse("accounts:delete_group", args=(self.group.pk,)),
                     reverse("accounts:update_group", args=(self.group.pk,))):
            self.assertNotContains(response, text)

    def test_view_group_all_perms_get(self):
        self.login("auth.view_group", "auth.change_group", "auth.delete_group")
        response = self.client.get(reverse("accounts:group", args=(self.group.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/group_detail.html")
        self.assertContains(response, self.group.name)
        for text in (reverse("accounts:delete_group", args=(self.group.pk,)),
                     reverse("accounts:update_group", args=(self.group.pk,))):
            self.assertContains(response, text)

    def test_view_provisioned_group_no_perms_get(self):
        self.login("auth.view_group")
        response = self.client.get(reverse("accounts:group", args=(self.group.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/group_detail.html")
        self.assertContains(response, self.group.name)
        for text in (reverse("accounts:delete_group", args=(self.group.pk,)),
                     reverse("accounts:update_group", args=(self.group.pk,))):
            self.assertNotContains(response, text)

    def test_view_provisioned_group_all_perms_get(self):
        self.login("auth.view_group", "auth.change_group", "auth.delete_group")
        response = self.client.get(reverse("accounts:group", args=(self.provisioned_group.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/group_detail.html")
        self.assertContains(response, self.provisioned_group.name)
        for text in (reverse("accounts:delete_group", args=(self.provisioned_group.pk,)),
                     reverse("accounts:update_group", args=(self.provisioned_group.pk,))):
            self.assertNotContains(response, text)

    # update

    def test_update_group_404(self):
        self.login("auth.change_group")
        response = self.client.get(reverse("accounts:update_group", args=(0,)))
        self.assertEqual(response.status_code, 404)

    def test_update_provisioned_group_404(self):
        self.login("auth.change_group")
        response = self.client.get(reverse("accounts:update_group", args=(self.provisioned_group.pk,)))
        self.assertEqual(response.status_code, 404)

    def test_update_group_get(self):
        self.login("auth.change_group")
        response = self.client.get(reverse("accounts:update_group", args=(self.group.pk,)))
        self.assertTemplateUsed(response, "accounts/group_form.html")
        form = response.context["form"]
        self.assertIn("name", form.fields)
        self.assertIn("permissions", form.fields)

    def test_user_update_username_error(self):
        self.login("auth.change_group")
        response = self.client.post(reverse("accounts:update_group", args=(self.group.pk,)),
                                    {"name": self.provisioned_group.name})
        self.assertTemplateUsed(response, "accounts/group_form.html")
        self.assertFormError(response.context["form"], "name", "Group with this Name already exists.")

    def test_update_group_ok(self):
        self.login("auth.change_group", "auth.view_group")
        name = get_random_string(12)
        response = self.client.post(reverse("accounts:update_group", args=(self.group.pk,)),
                                    {"name": name},
                                    follow=True)
        self.assertTemplateUsed(response, "accounts/group_detail.html")
        self.assertContains(response, name)

    # delete

    def test_delete_group_404(self):
        self.login("auth.delete_group")
        response = self.client.post(reverse("accounts:delete_group", args=(0,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_provisioned_group_404(self):
        self.login("auth.delete_group")
        response = self.client.post(reverse("accounts:delete_group", args=(self.provisioned_group.pk,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_group_ok(self):
        self.login("auth.delete_group", "auth.view_group")
        group_name = self.group.name
        response = self.client.post(reverse("accounts:delete_group", args=(self.group.pk,)),
                                    follow=True)
        self.assertTemplateUsed(response, "accounts/group_list.html")
        self.assertNotContains(response, group_name)
        self.assertContains(response, "Roles (2)")

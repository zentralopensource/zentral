from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.inventory.models import Tag
from .utils import force_realm_group, force_realm_group_tag_mapping


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class RealmGroupTagMappingManagementViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

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

    # list

    def test_realm_group_tag_mappings_redirect(self):
        self._login_redirect(reverse("mdm:realm_group_tag_mappings"))

    def test_realm_group_tag_mappings_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:realm_group_tag_mappings"))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.contrib.mdm.views.management.RealmGroupTagMappingListView.get_paginate_by")
    def test_realm_group_tag_mappings(self, get_paginate_by):
        get_paginate_by.return_value = 1
        rgtm_list = sorted(
            [force_realm_group_tag_mapping() for _ in range(3)],
            key=lambda o: (o.realm_group.realm.name.lower(), o.realm_group.display_name.lower())
        )
        self._login("mdm.view_realmgrouptagmapping")
        response = self.client.get(reverse("mdm:realm_group_tag_mappings"), {"page": 2})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/realmgrouptagmapping_list.html")
        self.assertNotContains(response, rgtm_list[0].realm_group.display_name)
        self.assertContains(response, rgtm_list[1].realm_group.display_name)
        self.assertNotContains(response, rgtm_list[2].realm_group.display_name)
        self.assertContains(response, "Group → Tag mappings (3)")
        self.assertContains(response, "page 2 of 3")

    # create

    def test_create_realm_group_tag_mapping_redirect(self):
        self._login_redirect(reverse("mdm:create_realm_group_tag_mapping"))

    def test_create_realm_group_tag_mapping_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:create_realm_group_tag_mapping"))
        self.assertEqual(response.status_code, 403)

    def test_create_realm_group_tag_mapping_get(self):
        self._login("mdm.add_realmgrouptagmapping")
        response = self.client.get(reverse("mdm:create_realm_group_tag_mapping"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/realmgrouptagmapping_form.html")
        self.assertContains(response, "Create Group → Tag mapping")

    def test_create_realm_group_tag_mapping_post(self):
        realm_group = force_realm_group()
        tag = Tag.objects.create(name=get_random_string(12))
        self._login("mdm.add_realmgrouptagmapping", "mdm.view_realmgrouptagmapping")
        response = self.client.post(reverse("mdm:create_realm_group_tag_mapping"),
                                    {"realm_group": realm_group.pk,
                                     "tag": tag.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/realmgrouptagmapping_list.html")
        self.assertContains(response, realm_group.display_name)
        self.assertContains(response, tag.name)

    # update rgtm

    def test_update_realm_group_tag_mapping_redirect(self):
        rgtm = force_realm_group_tag_mapping()
        self._login_redirect(reverse("mdm:update_realm_group_tag_mapping", args=(rgtm.pk,)))

    def test_update_realm_group_tag_mapping_permission_denied(self):
        rgtm = force_realm_group_tag_mapping()
        self._login()
        response = self.client.get(reverse("mdm:update_realm_group_tag_mapping", args=(rgtm.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_realm_group_tag_mapping_get(self):
        rgtm = force_realm_group_tag_mapping()
        self._login("mdm.change_realmgrouptagmapping")
        response = self.client.get(reverse("mdm:update_realm_group_tag_mapping", args=(rgtm.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/realmgrouptagmapping_form.html")
        self.assertContains(response, "Update Group → Tag mapping")
        self.assertContains(response, rgtm.realm_group.display_name)
        self.assertContains(response, rgtm.tag.name)

    def test_update_realm_group_tag_mapping_post(self):
        rgtm = force_realm_group_tag_mapping()
        new_realm_group = force_realm_group()
        new_tag = Tag.objects.create(name=get_random_string(12))
        self._login("mdm.change_realmgrouptagmapping", "mdm.view_realmgrouptagmapping")
        response = self.client.post(reverse("mdm:update_realm_group_tag_mapping", args=(rgtm.pk,)),
                                    {"realm_group": new_realm_group.pk,
                                     "tag": new_tag.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/realmgrouptagmapping_list.html")
        self.assertContains(response, new_realm_group.display_name)
        self.assertContains(response, new_tag.name)

    # delete rgtm

    def test_delete_realm_group_tag_mapping_redirect(self):
        rgtm = force_realm_group_tag_mapping()
        self._login_redirect(reverse("mdm:delete_realm_group_tag_mapping", args=(rgtm.pk,)))

    def test_delete_realm_group_tag_mapping_permission_denied(self):
        rgtm = force_realm_group_tag_mapping()
        self._login()
        response = self.client.get(reverse("mdm:delete_realm_group_tag_mapping", args=(rgtm.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_realm_group_tag_mapping_get(self):
        rgtm = force_realm_group_tag_mapping()
        self._login("mdm.delete_realmgrouptagmapping")
        response = self.client.get(reverse("mdm:delete_realm_group_tag_mapping", args=(rgtm.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/realmgrouptagmapping_confirm_delete.html")
        self.assertContains(response, "Delete Group → Tag mapping")

    def test_delete_realm_group_tag_mapping_post(self):
        rgtm = force_realm_group_tag_mapping()
        group_display_name = rgtm.realm_group.display_name
        self._login("mdm.delete_realmgrouptagmapping", "mdm.view_realmgrouptagmapping")
        response = self.client.post(reverse("mdm:delete_realm_group_tag_mapping", args=(rgtm.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/realmgrouptagmapping_list.html")
        self.assertNotContains(response, group_display_name)

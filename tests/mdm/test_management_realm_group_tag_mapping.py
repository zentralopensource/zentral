from unittest.mock import patch
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import User
from tests.zentral_test_utils.login_case import LoginCase
from zentral.contrib.inventory.models import Tag
from zentral.core.events.base import AuditEvent
from .utils import force_realm_group, force_realm_group_tag_mapping


class RealmGroupTagMappingManagementViewsTestCase(TestCase, LoginCase):
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
        return "mdm"

    # list

    def get_audit_event(self, post_event):
        # update_realm_tags() posts its own machine tag events, so the audit event is not
        # necessarily the first one
        events = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], AuditEvent)]
        self.assertEqual(len(events), 1)
        return events[0]

    def test_realm_group_tag_mappings_redirect(self):
        self.login_redirect("realm_group_tag_mappings")

    def test_realm_group_tag_mappings_permission_denied(self):
        self.login()
        response = self.client.get(reverse("mdm:realm_group_tag_mappings"))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.contrib.mdm.views.management.RealmGroupTagMappingListView.get_paginate_by")
    def test_realm_group_tag_mappings(self, get_paginate_by):
        get_paginate_by.return_value = 1
        rgtm_list = sorted(
            [force_realm_group_tag_mapping() for _ in range(3)],
            key=lambda o: (o.realm_group.realm.name.lower(), o.realm_group.display_name.lower())
        )
        self.login("mdm.view_realmgrouptagmapping")
        response = self.client.get(reverse("mdm:realm_group_tag_mappings"), {"page": 2})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/realmgrouptagmapping_list.html")
        self.assertNotContains(response, rgtm_list[0].realm_group.display_name)
        self.assertContains(response, rgtm_list[1].realm_group.display_name)
        self.assertNotContains(response, rgtm_list[2].realm_group.display_name)
        self.assertContains(response, "Group → Tag mappings (3)")
        self.assertContains(response, "page 2 of 3")

    def test_realm_group_tag_mappings_links(self):
        rgtm = force_realm_group_tag_mapping()
        self.login("mdm.view_realmgrouptagmapping", "mdm.add_realmgrouptagmapping",
                   "mdm.change_realmgrouptagmapping", "mdm.delete_realmgrouptagmapping")
        response = self.client.get(reverse("mdm:realm_group_tag_mappings"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/realmgrouptagmapping_list.html")
        self.assertContains(response, reverse("mdm:create_realm_group_tag_mapping"))
        self.assertContains(response, reverse("mdm:update_realm_group_tag_mapping", args=(rgtm.pk,)))
        self.assertContains(response, reverse("mdm:delete_realm_group_tag_mapping", args=(rgtm.pk,)))

    def test_realm_group_tag_mappings_no_links(self):
        rgtm = force_realm_group_tag_mapping()
        self.login("mdm.view_realmgrouptagmapping")
        response = self.client.get(reverse("mdm:realm_group_tag_mappings"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/realmgrouptagmapping_list.html")
        self.assertNotContains(response, reverse("mdm:create_realm_group_tag_mapping"))
        self.assertNotContains(response, reverse("mdm:update_realm_group_tag_mapping", args=(rgtm.pk,)))
        self.assertNotContains(response, reverse("mdm:delete_realm_group_tag_mapping", args=(rgtm.pk,)))

    def test_realm_group_tag_mappings_none_create_link(self):
        self.login("mdm.view_realmgrouptagmapping", "mdm.add_realmgrouptagmapping")
        response = self.client.get(reverse("mdm:realm_group_tag_mappings"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/realmgrouptagmapping_list.html")
        self.assertContains(response, "There are no Group → Tag mappings created.")
        self.assertContains(response, reverse("mdm:create_realm_group_tag_mapping"))

    def test_realm_group_tag_mappings_none_no_create_link(self):
        self.login("mdm.view_realmgrouptagmapping")
        response = self.client.get(reverse("mdm:realm_group_tag_mappings"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/realmgrouptagmapping_list.html")
        self.assertContains(response, "There are no Group → Tag mappings created.")
        self.assertNotContains(response, reverse("mdm:create_realm_group_tag_mapping"))

    # create

    def test_create_realm_group_tag_mapping_redirect(self):
        self.login_redirect("create_realm_group_tag_mapping")

    def test_create_realm_group_tag_mapping_permission_denied(self):
        self.login()
        response = self.client.get(reverse("mdm:create_realm_group_tag_mapping"))
        self.assertEqual(response.status_code, 403)

    def test_create_realm_group_tag_mapping_get(self):
        self.login("mdm.add_realmgrouptagmapping")
        response = self.client.get(reverse("mdm:create_realm_group_tag_mapping"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/realmgrouptagmapping_form.html")
        self.assertContains(response, "Create Group → Tag mapping")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_realm_group_tag_mapping_post(self, post_event):
        realm_group = force_realm_group()
        tag = Tag.objects.create(name=get_random_string(12))
        self.login("mdm.add_realmgrouptagmapping", "mdm.view_realmgrouptagmapping")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:create_realm_group_tag_mapping"),
                                        {"realm_group": realm_group.pk,
                                         "tag": tag.pk},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/realmgrouptagmapping_list.html")
        self.assertContains(response, realm_group.display_name)
        self.assertContains(response, tag.name)
        self.assertTrue(callbacks)
        event = self.get_audit_event(post_event)
        self.assertEqual(event.payload["action"], "created")
        self.assertEqual(event.payload["object"]["model"], "mdm.realmgrouptagmapping")
        new_value = event.payload["object"]["new_value"]
        self.assertEqual(new_value["realm_group"]["pk"], str(realm_group.pk))
        self.assertEqual(new_value["tag"], {"pk": tag.pk, "name": tag.name})

    # update rgtm

    def test_update_realm_group_tag_mapping_redirect(self):
        rgtm = force_realm_group_tag_mapping()
        self.login_redirect("update_realm_group_tag_mapping", rgtm.pk)

    def test_update_realm_group_tag_mapping_permission_denied(self):
        rgtm = force_realm_group_tag_mapping()
        self.login()
        response = self.client.get(reverse("mdm:update_realm_group_tag_mapping", args=(rgtm.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_realm_group_tag_mapping_get(self):
        rgtm = force_realm_group_tag_mapping()
        self.login("mdm.change_realmgrouptagmapping")
        response = self.client.get(reverse("mdm:update_realm_group_tag_mapping", args=(rgtm.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/realmgrouptagmapping_form.html")
        self.assertContains(response, "Update Group → Tag mapping")
        self.assertContains(response, rgtm.realm_group.display_name)
        self.assertContains(response, rgtm.tag.name)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_realm_group_tag_mapping_post(self, post_event):
        rgtm = force_realm_group_tag_mapping()
        prev_tag = rgtm.tag
        new_realm_group = force_realm_group()
        new_tag = Tag.objects.create(name=get_random_string(12))
        self.login("mdm.change_realmgrouptagmapping", "mdm.view_realmgrouptagmapping")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:update_realm_group_tag_mapping", args=(rgtm.pk,)),
                                        {"realm_group": new_realm_group.pk,
                                         "tag": new_tag.pk},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/realmgrouptagmapping_list.html")
        self.assertContains(response, new_realm_group.display_name)
        self.assertContains(response, new_tag.name)
        self.assertTrue(callbacks)
        event = self.get_audit_event(post_event)
        self.assertEqual(event.payload["action"], "updated")
        self.assertEqual(event.payload["object"]["prev_value"]["tag"]["pk"], prev_tag.pk)
        self.assertEqual(event.payload["object"]["new_value"]["tag"]["pk"], new_tag.pk)

    # delete rgtm

    def test_delete_realm_group_tag_mapping_redirect(self):
        rgtm = force_realm_group_tag_mapping()
        self.login_redirect("delete_realm_group_tag_mapping", rgtm.pk)

    def test_delete_realm_group_tag_mapping_permission_denied(self):
        rgtm = force_realm_group_tag_mapping()
        self.login()
        response = self.client.get(reverse("mdm:delete_realm_group_tag_mapping", args=(rgtm.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_realm_group_tag_mapping_get(self):
        rgtm = force_realm_group_tag_mapping()
        self.login("mdm.delete_realmgrouptagmapping")
        response = self.client.get(reverse("mdm:delete_realm_group_tag_mapping", args=(rgtm.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/realmgrouptagmapping_confirm_delete.html")
        self.assertContains(response, "Delete Group → Tag mapping")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_realm_group_tag_mapping_post(self, post_event):
        rgtm = force_realm_group_tag_mapping()
        group_display_name = rgtm.realm_group.display_name
        self.login("mdm.delete_realmgrouptagmapping", "mdm.view_realmgrouptagmapping")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:delete_realm_group_tag_mapping", args=(rgtm.pk,)),
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/realmgrouptagmapping_list.html")
        self.assertNotContains(response, group_display_name)
        self.assertTrue(callbacks)
        event = self.get_audit_event(post_event)
        self.assertEqual(event.payload["action"], "deleted")
        self.assertEqual(event.payload["object"]["prev_value"]["realm_group"]["display_name"],
                         group_display_name)

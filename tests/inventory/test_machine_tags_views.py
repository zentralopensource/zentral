from unittest.mock import patch

from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import User
from tests.zentral_test_utils.login_case import LoginCase
from zentral.contrib.inventory.events import MachineTagEvent
from zentral.contrib.inventory.models import MachineSnapshotCommit, MachineTag, Tag, Taxonomy


class MachineTagsViewsTestCase(TestCase, LoginCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "inventory"

    # utility methods

    def create_machine_snapshot(self, serial_number="1111"):
        source = {"module": "tests.zentral.com", "name": "Zentral Tests"}
        MachineSnapshotCommit.objects.commit_machine_snapshot_tree({
            "source": source,
            "business_unit": {"name": "yolo",
                              "reference": "fomo",
                              "source": source},
            "serial_number": serial_number,
        })

    # get machine tags

    def test_get_machine_tags_login_redirect(self):
        self.login_redirect("machine_tags", "1111")

    def test_get_machine_tags_permission_denied(self):
        self.login("inventory.view_machinesnapshot")
        response = self.client.get(reverse("inventory:machine_tags", args=("1111",)))
        self.assertEqual(response.status_code, 403)

    def test_get_machine_tags(self):
        immutable_tag = Tag.objects.create(name=get_random_string(12))
        MachineTag.objects.create(serial_number="1111", tag=immutable_tag)
        deletable_tag = Tag.objects.create(name=get_random_string(12))
        MachineTag.objects.create(serial_number="1111", tag=deletable_tag)
        available_tag = Tag.objects.create(name=get_random_string(12))
        unavailable_tag = Tag.objects.create(name=get_random_string(12))
        self.login_with_policy(
            "permit ("
            f' principal in Role::"{self.group.pk}",'
            f' action == Inventory::Action::"viewMachineTag",'
            '  resource'
            ");\n"
            "permit ("
            f' principal in Role::"{self.group.pk}",'
            f' action == Inventory::Action::"deleteMachineTag",'
            '  resource'
            ") when {"
            f'  context has tagName && context.tagName == "{deletable_tag.name}"\n'
            "};\n"
            "permit ("
            f' principal in Role::"{self.group.pk}",'
            f' action == Inventory::Action::"createMachineTag",'
            '  resource == Inventory::Machine::"1111"'
            ") when {"
            f' context has tagName && context.tagName == "{available_tag.name}"\n'
            "};\n"
        )
        response = self.client.get(reverse("inventory:machine_tags", args=("1111",)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_tags.html")
        self.assertNotContains(response, reverse("inventory:delete_machine_tag", args=("1111", immutable_tag.pk)))
        self.assertContains(response, immutable_tag.name)
        self.assertContains(response, reverse("inventory:delete_machine_tag", args=("1111", deletable_tag.pk)))
        self.assertContains(response, reverse("inventory:create_machine_tag", args=("1111", available_tag.pk)))
        self.assertNotContains(response, reverse("inventory:create_machine_tag", args=("1111", unavailable_tag.pk)))
        self.assertNotContains(response, unavailable_tag.name)

    # add tag

    def test_create_tag_redirect(self):
        self.login_redirect("create_machine_tag", "1111", 2222)

    def test_create_unknown_tag(self):
        self.login()
        response = self.client.post(reverse("inventory:create_machine_tag", args=("1111", 2222)))
        self.assertEqual(response.status_code, 404)  # unknown tag

    def test_create_tag_permission_denied(self):
        tag = Tag.objects.create(name=get_random_string(12))
        self.login_with_policy(
            "permit ("
            f' principal in Role::"{self.group.pk}",'
            f' action == Inventory::Action::"createMachineTag",'
            '  resource == Inventory::Machine::"1111"'
            ") when {"
            f' context has tagName && context.tagName == "yolo"\n'
            "};\n"
        )
        response = self.client.post(reverse("inventory:create_machine_tag", args=("1111", tag.pk)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_tag(self, post_event):
        tag = Tag.objects.create(name=get_random_string(12))
        self.login_with_policy(
            "permit ("
            f' principal in Role::"{self.group.pk}",'
            f' action == Inventory::Action::"viewMachineTag",'
            '  resource'
            ");\n"
            "permit ("
            f' principal in Role::"{self.group.pk}",'
            f' action == Inventory::Action::"createMachineTag",'
            '  resource == Inventory::Machine::"1111"'
            ") when {"
            f' context has tagName && context.tagName == "{tag.name}"\n'
            "};\n"
        )
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("inventory:create_machine_tag", args=("1111", tag.pk)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_tags.html")
        # events
        self.assertEqual(len(callbacks), 1)
        event, = [c.args[0] for c in post_event.call_args_list]
        self.assertIsInstance(event, MachineTagEvent)
        self.assertEqual(
            event.payload,
            {'action': 'added', 'tag': {'name': tag.name, 'pk': tag.pk}}
        )

    # delete tag

    def test_delete_tag_redirect(self):
        self.login_redirect("delete_machine_tag", "1111", 2222)

    def test_delete_unknown_tag(self):
        self.login()
        response = self.client.post(reverse("inventory:delete_machine_tag", args=("1111", 2222)))
        self.assertEqual(response.status_code, 404)  # unknown tag

    def test_delete_tag_permission_denied(self):
        self.login_with_policy(
            "permit ("
            f' principal in Role::"{self.group.pk}",'
            f' action == Inventory::Action::"deleteMachineTag",'
            '  resource == Inventory::Machine::"1111"'
            ") when {"
            f' context has tagName && context.tagName == "yolo"\n'
            "};\n"
        )
        tag = Tag.objects.create(name=get_random_string(12))
        response = self.client.post(reverse("inventory:delete_machine_tag", args=("1111", tag.pk)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_tag(self, post_event):
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        tag = Tag.objects.create(taxonomy=taxonomy, name=get_random_string(12))
        MachineTag.objects.create(serial_number="1111", tag=tag)
        qs = MachineTag.objects.filter(serial_number="1111")
        self.assertEqual(qs.count(), 1)
        self.login_with_policy(
            "permit ("
            f' principal in Role::"{self.group.pk}",'
            f' action == Inventory::Action::"viewMachineTag",'
            '  resource'
            ");\n"
            "permit ("
            f' principal in Role::"{self.group.pk}",'
            f' action == Inventory::Action::"deleteMachineTag",'
            '  resource == Inventory::Machine::"1111"'
            ") when {"
            f' context has taxonomyName && context.taxonomyName == "{taxonomy.name}"\n'
            "};\n"
        )
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("inventory:delete_machine_tag", args=("1111", tag.pk)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_tags.html")
        # events
        self.assertEqual(len(callbacks), 1)
        event, = [c.args[0] for c in post_event.call_args_list]
        self.assertIsInstance(event, MachineTagEvent)
        self.assertEqual(
            event.payload,
            {'action': 'removed',
             'tag': {'pk': tag.pk, 'name': tag.name},
             'taxonomy': {'pk': taxonomy.pk, 'name': taxonomy.name}}
        )

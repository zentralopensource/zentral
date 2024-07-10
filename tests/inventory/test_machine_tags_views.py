from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from zentral.contrib.inventory.models import MachineSnapshotCommit, MachineTag, MetaBusinessUnit, Tag
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MachineTagsViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
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
        self._login_redirect(reverse("inventory:machine_tags", args=("1111",)))

    def test_get_machine_tags_permission_denied(self):
        self._login("inventory.view_machinesnapshot")
        response = self.client.get(reverse("inventory:machine_tags", args=("1111",)))
        self.assertEqual(response.status_code, 403)

    def test_get_machine_tags(self):
        self._login(
            "inventory.view_machinetag",
            "inventory.add_machinetag",
            "inventory.change_machinetag",
            "inventory.delete_machinetag",
            "inventory.add_tag",
        )
        response = self.client.get(reverse("inventory:machine_tags", args=("1111",)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_tags.html")

    # new tag

    def test_post_new_tag(self):
        qs = MachineTag.objects.filter(serial_number="1111")
        self.assertEqual(qs.count(), 0)
        self._login(
            "inventory.view_machinetag",
            "inventory.add_machinetag",
            "inventory.change_machinetag",
            "inventory.delete_machinetag",
            "inventory.add_tag",
        )
        name = get_random_string(12)
        response = self.client.post(reverse("inventory:machine_tags", args=("1111",)),
                                    {"new_tag_name": name,
                                     "new_tag_color": "123456"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_tags.html")
        self.assertContains(response, name)
        self.assertEqual(qs.count(), 1)
        machine_tag = qs.first()
        self.assertEqual(machine_tag.tag.name, name)

    def test_post_new_tag_or_existing_error(self):
        qs = MachineTag.objects.filter(serial_number="1111")
        self.assertEqual(qs.count(), 0)
        self._login(
            "inventory.view_machinetag",
            "inventory.add_machinetag",
            "inventory.change_machinetag",
            "inventory.delete_machinetag",
            "inventory.add_tag",
        )
        response = self.client.post(reverse("inventory:machine_tags", args=("1111",)),
                                    {},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_tags.html")
        self.assertEqual(qs.count(), 0)
        err_msg = "You must select an existing tag or enter a name for a new tag"
        self.assertFormError(response.context["form"], "existing_tag", err_msg)
        self.assertFormError(response.context["form"], "new_tag_name", err_msg)

    def test_post_new_existing_tag_error(self):
        qs = MachineTag.objects.filter(serial_number="1111")
        self.assertEqual(qs.count(), 0)
        self._login(
            "inventory.view_machinetag",
            "inventory.add_machinetag",
            "inventory.change_machinetag",
            "inventory.delete_machinetag",
            "inventory.add_tag",
        )
        tag = Tag.objects.create(name=get_random_string(12))
        response = self.client.post(reverse("inventory:machine_tags", args=("1111",)),
                                    {"new_tag_name": tag.name},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_tags.html")
        self.assertEqual(qs.count(), 0)
        self.assertFormError(response.context["form"], "new_tag_name",
                             "A tag with the same name or slug already exists")

    # existing tag

    def test_post_existing_tag(self):
        self.create_machine_snapshot(serial_number="1111")
        qs = MachineTag.objects.filter(serial_number="1111")
        self.assertEqual(qs.count(), 0)
        tag = Tag.objects.create(name=get_random_string(12))
        self._login(
            "inventory.view_machinetag",
            "inventory.add_machinetag",
            "inventory.change_machinetag",
            "inventory.delete_machinetag",
            "inventory.add_tag",
        )
        response = self.client.post(reverse("inventory:machine_tags", args=("1111",)),
                                    {"existing_tag": tag.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_tags.html")
        self.assertEqual(qs.count(), 1)
        machine_tag = qs.first()
        self.assertEqual(machine_tag.tag, tag)

    def test_post_existing_tag_mbu_error(self):
        self.create_machine_snapshot(serial_number="1111")
        qs = MachineTag.objects.filter(serial_number="1111")
        self.assertEqual(qs.count(), 0)
        tag = Tag.objects.create(name=get_random_string(12),
                                 meta_business_unit=MetaBusinessUnit.objects.create(name=get_random_string(12)))
        self._login(
            "inventory.view_machinetag",
            "inventory.add_machinetag",
            "inventory.change_machinetag",
            "inventory.delete_machinetag",
            "inventory.add_tag",
        )
        response = self.client.post(reverse("inventory:machine_tags", args=("1111",)),
                                    {"existing_tag": tag.pk},
                                    follow=True)
        self.assertEqual(qs.count(), 0)
        self.assertFormError(response.context["form"], "existing_tag",
                             "Select a valid choice. That choice is not one of the available choices.")

    def test_post_existing_tag_duplicate(self):
        self.create_machine_snapshot(serial_number="1111")
        qs = MachineTag.objects.filter(serial_number="1111")
        tag = Tag.objects.create(name=get_random_string(12))
        MachineTag.objects.create(serial_number="1111", tag=tag)
        self.assertEqual(qs.count(), 1)
        self._login(
            "inventory.view_machinetag",
            "inventory.add_machinetag",
            "inventory.change_machinetag",
            "inventory.delete_machinetag",
            "inventory.add_tag",
        )
        response = self.client.post(reverse("inventory:machine_tags", args=("1111",)),
                                    {"existing_tag": tag.pk},
                                    follow=True)
        self.assertEqual(qs.count(), 1)
        self.assertFormError(response.context["form"], "existing_tag",
                             "Select a valid choice. That choice is not one of the available choices.")

    # remove tag

    def test_remove_tag_redirect(self):
        self._login_redirect(reverse("inventory:remove_machine_tag", args=("1111", 2222)))

    def test_remove_tag_permission_denied(self):
        self._login()
        response = self.client.post(reverse("inventory:remove_machine_tag", args=("1111", 2222)))
        self.assertEqual(response.status_code, 403)

    def test_remove_tag(self):
        tag = Tag.objects.create(name=get_random_string(12))
        MachineTag.objects.create(serial_number="1111", tag=tag)
        qs = MachineTag.objects.filter(serial_number="1111")
        self.assertEqual(qs.count(), 1)
        self._login(
            "inventory.view_machinetag",
            "inventory.add_machinetag",
            "inventory.change_machinetag",
            "inventory.delete_machinetag",
            "inventory.add_tag",
        )
        response = self.client.post(reverse("inventory:remove_machine_tag", args=("1111", tag.pk)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_tags.html")

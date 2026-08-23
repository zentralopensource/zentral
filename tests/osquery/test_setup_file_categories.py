from unittest.mock import patch
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import User
from tests.osquery.utils import assert_audit_event
from tests.zentral_test_utils.login_case import LoginCase
from zentral.contrib.osquery.models import FileCategory
from zentral.core.events.base import AuditEvent


class OsquerySetupFileCategoriesViewsTestCase(TestCase, LoginCase):
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

    def _force_file_category(self):
        return FileCategory.objects.create(
            name=get_random_string(12),
            file_paths=[get_random_string(16) for i in range(3)]
        )

    # create file_category

    def test_create_file_category_redirect(self):
        self.login_redirect("create_file_category")

    def test_create_file_category_permission_denied(self):
        self.login()
        response = self.client.get(reverse("osquery:create_file_category"))
        self.assertEqual(response.status_code, 403)

    def test_create_file_category_get(self):
        self.login("osquery.add_filecategory")
        response = self.client.get(reverse("osquery:create_file_category"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/filecategory_form.html")
        self.assertContains(response, "Create File category")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_file_category_post(self, post_event):
        self.login("osquery.add_filecategory", "osquery.view_filecategory")
        file_category_name = get_random_string(64)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("osquery:create_file_category"),
                                        {"name": file_category_name,
                                         "file_paths": "yolo, fomo"},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "osquery/filecategory_detail.html")
        self.assertContains(response, file_category_name)
        file_category = response.context["object"]
        self.assertEqual(file_category.name, file_category_name)
        self.assertEqual(file_category.file_paths, ["yolo", "fomo"])
        self.assertEqual(file_category.access_monitoring, False)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "osquery.filecategory",
                 "pk": str(file_category.pk),
                 "new_value": {
                     "pk": file_category.pk,
                     "name": file_category_name,
                     "slug": file_category.slug,
                     "description": "",
                     "file_paths": ["fomo", "yolo"],
                     "exclude_paths": [],
                     "file_paths_queries": [],
                     "access_monitoring": False,
                     "created_at": file_category.created_at.isoformat(),
                     "updated_at": file_category.updated_at.isoformat(),
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"osquery_file_category": [str(file_category.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["osquery", "zentral"])

    # update file category

    def test_update_file_category_redirect(self):
        file_category = self._force_file_category()
        self.login_redirect("update_file_category", file_category.pk)

    def test_update_file_category_permission_denied(self):
        file_category = self._force_file_category()
        self.login()
        response = self.client.get(reverse("osquery:update_file_category", args=(file_category.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_file_category_get(self):
        file_category = self._force_file_category()
        self.login("osquery.change_filecategory")
        response = self.client.get(reverse("osquery:update_file_category", args=(file_category.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/filecategory_form.html")
        self.assertContains(response, "Update File category")
        self.assertContains(response, file_category.name)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_file_category_post(self, post_event):
        file_category = self._force_file_category()
        prev_value = file_category.serialize_for_event()
        self.login("osquery.change_filecategory", "osquery.view_filecategory")
        new_name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("osquery:update_file_category", args=(file_category.pk,)),
                                        {"name": new_name,
                                         "file_paths": "yolo, 2020forever",
                                         "access_monitoring": "on"},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "osquery/filecategory_detail.html")
        self.assertContains(response, new_name)
        file_category = response.context["object"]
        self.assertEqual(file_category.name, new_name)
        self.assertEqual(file_category.file_paths, ["yolo", "2020forever"])
        self.assertEqual(file_category.access_monitoring, True)
        payload, metadata = assert_audit_event(self, post_event, "updated", file_category, prev_value=prev_value)
        self.assertFalse(payload["object"]["prev_value"]["access_monitoring"])
        self.assertTrue(payload["object"]["new_value"]["access_monitoring"])
        self.assertEqual(metadata["objects"], {"osquery_file_category": [str(file_category.pk)]})

    # delete file category

    def test_delete_file_category_redirect(self):
        file_category = self._force_file_category()
        self.login_redirect("delete_file_category", file_category.pk)

    def test_delete_file_category_permission_denied(self):
        file_category = self._force_file_category()
        self.login()
        response = self.client.get(reverse("osquery:delete_file_category", args=(file_category.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_file_category_get(self):
        file_category = self._force_file_category()
        self.login("osquery.delete_filecategory")
        response = self.client.get(reverse("osquery:delete_file_category", args=(file_category.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/filecategory_confirm_delete.html")
        self.assertContains(response, file_category.name)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_file_category_post(self, post_event):
        file_category = self._force_file_category()
        prev_value = file_category.serialize_for_event()
        self.login("osquery.delete_filecategory", "osquery.view_filecategory")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("osquery:delete_file_category", args=(file_category.pk,)),
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "osquery/filecategory_list.html")
        self.assertEqual(FileCategory.objects.filter(pk=file_category.pk).count(), 0)
        self.assertNotContains(response, file_category.name)
        _, metadata = assert_audit_event(self, post_event, "deleted", file_category, prev_value=prev_value)
        self.assertEqual(metadata["objects"], {"osquery_file_category": [str(file_category.pk)]})

    # file category list

    def test_file_category_list_redirect(self):
        self.login_redirect("file_categories")

    def test_file_category_permission_denied(self):
        self.login()
        response = self.client.get(reverse("osquery:file_categories"))
        self.assertEqual(response.status_code, 403)

    def test_file_category_list(self):
        file_category = self._force_file_category()
        self.login("osquery.view_filecategory")
        response = self.client.get(reverse("osquery:file_categories"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/filecategory_list.html")
        self.assertIn(file_category, response.context["object_list"])
        self.assertContains(response, file_category.name)

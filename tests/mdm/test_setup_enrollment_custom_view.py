from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.core.events.base import AuditEvent
from zentral.contrib.inventory.models import MetaBusinessUnit
from .utils import force_dep_enrollment, force_dep_enrollment_custom_view, force_enrollment_custom_view


class EnrollmentCustomViewManagementViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))

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

    # Enrollment custom views

    def test_enrollment_custom_views_redirect(self):
        self._login_redirect(reverse("mdm:enrollment_custom_views"))

    def test_enrollment_custom_views_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:enrollment_custom_views"))
        self.assertEqual(response.status_code, 403)

    def test_enrollment_custom_views_no_links(self):
        ecv = force_enrollment_custom_view()
        self._login("mdm.view_enrollmentcustomview")
        response = self.client.get(reverse("mdm:enrollment_custom_views"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrollmentcustomview_list.html")
        self.assertContains(response, ecv.name)
        self.assertNotContains(response, reverse("mdm:update_enrollment_custom_view", args=(ecv.pk,)))
        self.assertNotContains(response, reverse("mdm:delete_enrollment_custom_view", args=(ecv.pk,)))

    def test_enrollment_custom_views_all_links(self):
        decv1 = force_dep_enrollment_custom_view(force_dep_enrollment(self.mbu))
        ecv1 = decv1.custom_view
        ecv2 = force_enrollment_custom_view()
        self._login(
            "mdm.view_enrollmentcustomview",
            "mdm.change_enrollmentcustomview",
            "mdm.delete_enrollmentcustomview"
        )
        response = self.client.get(reverse("mdm:enrollment_custom_views"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrollmentcustomview_list.html")
        self.assertContains(response, ecv1.name)
        self.assertContains(response, ecv2.name)
        self.assertContains(response, reverse("mdm:update_enrollment_custom_view", args=(ecv1.pk,)))
        self.assertNotContains(response, reverse("mdm:delete_enrollment_custom_view", args=(ecv1.pk,)))
        self.assertContains(response, reverse("mdm:update_enrollment_custom_view", args=(ecv2.pk,)))
        self.assertContains(response, reverse("mdm:delete_enrollment_custom_view", args=(ecv2.pk,)))

    # create enrollment custom view

    def test_create_enrollment_custom_view_redirect(self):
        self._login_redirect(reverse("mdm:create_enrollment_custom_view"))

    def test_create_enrollment_custom_view_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:create_enrollment_custom_view"))
        self.assertEqual(response.status_code, 403)

    def test_create_enrollment_custom_view_get(self):
        self._login("mdm.add_enrollmentcustomview")
        response = self.client.get(reverse("mdm:create_enrollment_custom_view"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrollmentcustomview_form.html")
        self.assertContains(response, "Create enrollment custom view")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_enrollment_custom_view_post(self, post_event):
        self._login("mdm.add_enrollmentcustomview", "mdm.view_enrollmentcustomview")
        name = get_random_string(12)
        description = get_random_string(12)
        html = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:create_enrollment_custom_view"),
                                        {"name": name,
                                         "description": description,
                                         "html": html,
                                         "requires_authentication": "on"},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "mdm/enrollmentcustomview_detail.html")
        ecv = response.context["object"]
        self.assertEqual(ecv.name, name)
        self.assertEqual(ecv.description, description)
        self.assertEqual(ecv.html, html)
        self.assertTrue(ecv.requires_authentication)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "mdm.enrollmentcustomview",
                 "pk": str(ecv.pk),
                 "new_value": {
                     "pk": str(ecv.pk),
                     "name": name,
                     "description": description,
                     "html": html,
                     "requires_authentication": ecv.requires_authentication,
                     "created_at": ecv.created_at,
                     "updated_at": ecv.updated_at
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_enrollment_custom_view": [str(ecv.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # enrollment custom view

    def test_enrollment_custom_view_redirect(self):
        ecv = force_enrollment_custom_view()
        self._login_redirect(reverse("mdm:enrollment_custom_view", args=(ecv.pk,)))

    def test_enrollment_custom_view_permission_denied(self):
        ecv = force_enrollment_custom_view()
        self._login()
        response = self.client.get(reverse("mdm:enrollment_custom_view", args=(ecv.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_enrollment_custom_view_get(self):
        ecv = force_enrollment_custom_view()
        self._login("mdm.view_enrollmentcustomview", "mdm.delete_enrollmentcustomview")
        response = self.client.get(reverse("mdm:enrollment_custom_view", args=(ecv.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrollmentcustomview_detail.html")
        self.assertContains(response, ecv.name)
        self.assertContains(response, reverse("mdm:delete_enrollment_custom_view", args=(ecv.pk,)))
        self.assertNotContains(response, reverse("mdm:update_enrollment_custom_view", args=(ecv.pk,)))

    def test_enrollment_custom_view_get_no_perm_no_delete_link(self):
        ecv = force_enrollment_custom_view()
        self._login("mdm.view_enrollmentcustomview", "mdm.change_enrollmentcustomview")
        response = self.client.get(reverse("mdm:enrollment_custom_view", args=(ecv.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrollmentcustomview_detail.html")
        self.assertContains(response, ecv.name)
        self.assertNotContains(response, reverse("mdm:delete_enrollment_custom_view", args=(ecv.pk,)))
        self.assertContains(response, reverse("mdm:update_enrollment_custom_view", args=(ecv.pk,)))

    def test_enrollment_custom_view_get_cannot_be_deleted_no_delete_link(self):
        decv = force_dep_enrollment_custom_view(force_dep_enrollment(self.mbu))
        ecv = decv.custom_view
        self._login("mdm.view_enrollmentcustomview", "mdm.delete_enrollmentcustomview")
        response = self.client.get(reverse("mdm:enrollment_custom_view", args=(ecv.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrollmentcustomview_detail.html")
        self.assertContains(response, ecv.name)
        self.assertNotContains(response, reverse("mdm:delete_enrollment_custom_view", args=(ecv.pk,)))
        self.assertNotContains(response, reverse("mdm:update_enrollment_custom_view", args=(ecv.pk,)))

    # update FileVault configuration

    def test_update_enrollment_custom_view_redirect(self):
        ecv = force_enrollment_custom_view()
        self._login_redirect(reverse("mdm:update_enrollment_custom_view", args=(ecv.pk,)))

    def test_update_enrollment_custom_view_permission_denied(self):
        ecv = force_enrollment_custom_view()
        self._login()
        response = self.client.get(reverse("mdm:update_enrollment_custom_view", args=(ecv.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_enrollment_custom_view_get(self):
        ecv = force_enrollment_custom_view()
        self._login("mdm.change_enrollmentcustomview")
        response = self.client.get(reverse("mdm:update_enrollment_custom_view", args=(ecv.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrollmentcustomview_form.html")
        self.assertContains(response, "Update enrollment custom view")
        self.assertContains(response, ecv.name)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_enrollment_custom_view_post(self, post_event):
        ecv = force_enrollment_custom_view()
        prev_value = ecv.serialize_for_event()
        self.assertFalse(ecv.requires_authentication)
        self._login("mdm.change_enrollmentcustomview", "mdm.view_enrollmentcustomview")
        new_name = get_random_string(12)
        new_description = get_random_string(12)
        new_html = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:update_enrollment_custom_view", args=(ecv.pk,)),
                                        {"name": new_name,
                                         "description": new_description,
                                         "html": new_html,
                                         "requires_authentication": "on"},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "mdm/enrollmentcustomview_detail.html")
        ecv2 = response.context["object"]
        self.assertEqual(ecv2, ecv)
        self.assertEqual(ecv2.name, new_name)
        self.assertEqual(ecv2.description, new_description)
        self.assertEqual(ecv2.html, new_html)
        self.assertTrue(ecv2.requires_authentication)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "mdm.enrollmentcustomview",
                 "pk": str(ecv2.pk),
                 "new_value": {
                     "pk": str(ecv2.pk),
                     "name": new_name,
                     "description": new_description,
                     "html": new_html,
                     "requires_authentication": True,
                     "created_at": ecv2.created_at,
                     "updated_at": ecv2.updated_at
                 },
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_enrollment_custom_view": [str(ecv.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # delete enrollment custom view

    def test_delete_enrollment_custom_view_redirect(self):
        ecv = force_enrollment_custom_view()
        self._login_redirect(reverse("mdm:delete_enrollment_custom_view", args=(ecv.pk,)))

    def test_delete_enrollment_custom_view_permission_denied(self):
        ecv = force_enrollment_custom_view()
        self._login()
        response = self.client.get(reverse("mdm:delete_enrollment_custom_view", args=(ecv.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_enrollment_custom_view_404(self):
        decv = force_dep_enrollment_custom_view(force_dep_enrollment(self.mbu))
        ecv = decv.custom_view
        self._login("mdm.delete_enrollmentcustomview")
        response = self.client.get(reverse("mdm:delete_enrollment_custom_view", args=(ecv.pk,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_enrollment_custom_view_get(self):
        ecv = force_enrollment_custom_view()
        self._login("mdm.delete_enrollmentcustomview")
        response = self.client.get(reverse("mdm:delete_enrollment_custom_view", args=(ecv.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrollmentcustomview_confirm_delete.html")
        self.assertContains(response, "Delete enrollment custom view")
        self.assertContains(response, ecv.name)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_enrollment_custom_view_post(self, post_event):
        ecv = force_enrollment_custom_view()
        prev_value = ecv.serialize_for_event()
        self._login("mdm.delete_enrollmentcustomview", "mdm.view_enrollmentcustomview")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:delete_enrollment_custom_view", args=(ecv.pk,)),
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "mdm/enrollmentcustomview_list.html")
        self.assertNotContains(response, ecv.name)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "mdm.enrollmentcustomview",
                 "pk": str(ecv.pk),
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_enrollment_custom_view": [str(ecv.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

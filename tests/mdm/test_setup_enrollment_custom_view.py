from typing_extensions import override
from unittest.mock import patch
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from tests.zentral_test_utils.assertions.event_assertions import EventAssertions
from tests.zentral_test_utils.login_case import LoginCase
from zentral.core.events.base import AuditEvent
from zentral.contrib.inventory.models import MetaBusinessUnit
from .utils import force_dep_enrollment, force_dep_enrollment_custom_view, force_enrollment_custom_view


class EnrollmentCustomViewManagementViewsTestCase(TestCase, LoginCase, EventAssertions):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))

    # LoginCase implementation

    @override
    def _get_user(self):
        return self.user

    @override
    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "mdm"

    # Enrollment custom views

    def test_enrollment_custom_views_redirect(self):
        self.login_redirect("enrollment_custom_views")

    def test_enrollment_custom_views_permission_denied(self):
        self.login()
        self.permission_denied("enrollment_custom_views")

    def test_enrollment_custom_views_no_links(self):
        ecv = force_enrollment_custom_view()
        self.login("mdm.view_enrollmentcustomview")
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
        self.login(
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
        self.login_redirect("create_enrollment_custom_view")

    def test_create_enrollment_custom_view_permission_denied(self):
        self.login() 
        self.permission_denied("create_enrollment_custom_view")

    def test_create_enrollment_custom_view_get(self):
        self.login("mdm.add_enrollmentcustomview")
        response = self.client.get(reverse("mdm:create_enrollment_custom_view"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrollmentcustomview_form.html")
        self.assertContains(response, "Create enrollment custom view")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_enrollment_custom_view_post(self, post_event):
        self.login("mdm.add_enrollmentcustomview", "mdm.view_enrollmentcustomview")
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
        self.assertTemplateUsed(response, "mdm/enrollmentcustomview_detail.html")
        ecv = response.context["object"]
        self.assertEqual(ecv.name, name)
        self.assertEqual(ecv.description, description)
        self.assertEqual(ecv.html, html)
        self.assertTrue(ecv.requires_authentication)

        self.assert_events_published(
            expected_number_of_events=1,
            callbacks=callbacks,
            post_event=post_event)
        self.assert_is_audit_event(
            post_event=post_event,
            expected_payload={
                "action": "created",
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
                }
            },
            expected_metadata_objects={"mdm_enrollment_custom_view": [str(ecv.pk)]},
            expected_tags=["mdm", "zentral"])

    # enrollment custom view

    def test_enrollment_custom_view_redirect(self):
        ecv = force_enrollment_custom_view()
        self.login_redirect("enrollment_custom_view", ecv.pk)

    def test_enrollment_custom_view_permission_denied(self):
        ecv = force_enrollment_custom_view()
        self.login()
        self.permission_denied("enrollment_custom_view", ecv.pk)

    def test_enrollment_custom_view_get(self):
        ecv = force_enrollment_custom_view()
        self.login("mdm.view_enrollmentcustomview", "mdm.delete_enrollmentcustomview")
        response = self.client.get(reverse("mdm:enrollment_custom_view", args=(ecv.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrollmentcustomview_detail.html")
        self.assertContains(response, ecv.name)
        self.assertContains(response, reverse("mdm:delete_enrollment_custom_view", args=(ecv.pk,)))
        self.assertNotContains(response, reverse("mdm:update_enrollment_custom_view", args=(ecv.pk,)))

    def test_enrollment_custom_view_get_no_perm_no_delete_link(self):
        ecv = force_enrollment_custom_view()
        self.login("mdm.view_enrollmentcustomview", "mdm.change_enrollmentcustomview")
        response = self.client.get(reverse("mdm:enrollment_custom_view", args=(ecv.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrollmentcustomview_detail.html")
        self.assertContains(response, ecv.name)
        self.assertNotContains(response, reverse("mdm:delete_enrollment_custom_view", args=(ecv.pk,)))
        self.assertContains(response, reverse("mdm:update_enrollment_custom_view", args=(ecv.pk,)))

    def test_enrollment_custom_view_get_cannot_be_deleted_no_delete_link(self):
        decv = force_dep_enrollment_custom_view(force_dep_enrollment(self.mbu))
        ecv = decv.custom_view
        self.login("mdm.view_enrollmentcustomview", "mdm.delete_enrollmentcustomview")
        response = self.client.get(reverse("mdm:enrollment_custom_view", args=(ecv.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrollmentcustomview_detail.html")
        self.assertContains(response, ecv.name)
        self.assertNotContains(response, reverse("mdm:delete_enrollment_custom_view", args=(ecv.pk,)))
        self.assertNotContains(response, reverse("mdm:update_enrollment_custom_view", args=(ecv.pk,)))

    # update FileVault configuration

    def test_update_enrollment_custom_view_redirect(self):
        ecv = force_enrollment_custom_view()
        self.login_redirect("update_enrollment_custom_view", ecv.pk)

    def test_update_enrollment_custom_view_permission_denied(self):
        ecv = force_enrollment_custom_view()
        self.login()
        self.permission_denied("update_enrollment_custom_view", ecv.pk)

    def test_update_enrollment_custom_view_get(self):
        ecv = force_enrollment_custom_view()
        self.login("mdm.change_enrollmentcustomview")
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
        self.login("mdm.change_enrollmentcustomview", "mdm.view_enrollmentcustomview")
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
        self.assertTemplateUsed(response, "mdm/enrollmentcustomview_detail.html")
        ecv2 = response.context["object"]
        self.assertEqual(ecv2, ecv)
        self.assertEqual(ecv2.name, new_name)
        self.assertEqual(ecv2.description, new_description)
        self.assertEqual(ecv2.html, new_html)
        self.assertTrue(ecv2.requires_authentication)

        self.assert_events_published(
            expected_number_of_events=1,
            callbacks=callbacks,
            post_event=post_event)
        self.assert_is_audit_event(
            post_event=post_event,
            expected_payload={
                "action": "updated",
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
                }
            },
            expected_metadata_objects={"mdm_enrollment_custom_view": [str(ecv.pk)]},
            expected_tags=["mdm", "zentral"])

    # delete enrollment custom view

    def test_delete_enrollment_custom_view_redirect(self):
        ecv = force_enrollment_custom_view()
        self.login_redirect("delete_enrollment_custom_view", ecv.pk)

    def test_delete_enrollment_custom_view_permission_denied(self):
        ecv = force_enrollment_custom_view()
        self.login()
        self.permission_denied("delete_enrollment_custom_view", ecv.pk)

    def test_delete_enrollment_custom_view_404(self):
        decv = force_dep_enrollment_custom_view(force_dep_enrollment(self.mbu))
        ecv = decv.custom_view
        self.login("mdm.delete_enrollmentcustomview")
        response = self.client.get(reverse("mdm:delete_enrollment_custom_view", args=(ecv.pk,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_enrollment_custom_view_get(self):
        ecv = force_enrollment_custom_view()
        self.login("mdm.delete_enrollmentcustomview")
        response = self.client.get(reverse("mdm:delete_enrollment_custom_view", args=(ecv.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrollmentcustomview_confirm_delete.html")
        self.assertContains(response, "Delete enrollment custom view")
        self.assertContains(response, ecv.name)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_enrollment_custom_view_post(self, post_event):
        ecv = force_enrollment_custom_view()
        prev_value = ecv.serialize_for_event()
        self.login("mdm.delete_enrollmentcustomview", "mdm.view_enrollmentcustomview")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:delete_enrollment_custom_view", args=(ecv.pk,)),
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrollmentcustomview_list.html")
        self.assertNotContains(response, ecv.name)

        self.assert_events_published(
            expected_number_of_events=1,
            callbacks=callbacks,
            post_event=post_event)
        self.assert_is_audit_event(
            post_event=post_event,
            expected_payload={
                "action": "deleted",
                "object": {
                    "model": "mdm.enrollmentcustomview",
                    "pk": str(ecv.pk),
                    "prev_value": prev_value,
                }
            },
            expected_metadata_objects={"mdm_enrollment_custom_view": [str(ecv.pk)]},
            expected_tags=["mdm", "zentral"])

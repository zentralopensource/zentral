from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.core.events.base import AuditEvent
from zentral.contrib.inventory.models import MetaBusinessUnit
from .utils import force_dep_enrollment, force_dep_enrollment_custom_view, force_enrollment_custom_view


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MDMDEPEnrollmentCustomViewSetupViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        mbu.create_enrollment_business_unit()
        cls.dep_enrollment = force_dep_enrollment(mbu)

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

    # create DEP enrollment custom view

    def test_create_dep_enrollment_custom_view_redirect(self):
        self._login_redirect(reverse("mdm:create_dep_enrollment_custom_view", args=(self.dep_enrollment.pk,)))

    def test_create_dep_enrollment_custom_view_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:create_dep_enrollment_custom_view", args=(self.dep_enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_create_dep_enrollment_custom_view_get(self):
        self._login("mdm.add_depenrollmentcustomview")
        response = self.client.get(reverse("mdm:create_dep_enrollment_custom_view", args=(self.dep_enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollmentcustomview_form.html")
        self.assertContains(response, "Create custom view")

    def test_create_dep_enrollment_custom_view_same_custom_view_error(self):
        self._login("mdm.add_depenrollmentcustomview", "mdm.view_depenrollment")
        decv = force_dep_enrollment_custom_view(self.dep_enrollment)
        response = self.client.post(reverse("mdm:create_dep_enrollment_custom_view", args=(self.dep_enrollment.pk,)),
                                    {"custom_view": decv.custom_view.pk,
                                     "weight": 10},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollmentcustomview_form.html")
        self.assertFormError(response.context["form"], "custom_view",
                             "Select a valid choice. That choice is not one of the available choices.")

    def test_create_dep_enrollment_custom_view_same_weight_error(self):
        self._login("mdm.add_depenrollmentcustomview", "mdm.view_depenrollment")
        decv = force_dep_enrollment_custom_view(self.dep_enrollment)
        cv = force_enrollment_custom_view()
        response = self.client.post(reverse("mdm:create_dep_enrollment_custom_view", args=(self.dep_enrollment.pk,)),
                                    {"custom_view": cv.pk,
                                     "weight": decv.weight},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollmentcustomview_form.html")
        self.assertFormError(response.context["form"], "weight", "A custom view with this weight already exists.")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_dep_enrollment_custom_view(self, post_event):
        self._login("mdm.add_depenrollmentcustomview", "mdm.view_depenrollment")
        cv = force_enrollment_custom_view()
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:create_dep_enrollment_custom_view",
                                                args=(self.dep_enrollment.pk,)),
                                        {"custom_view": cv.pk,
                                         "weight": 17},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_detail.html")
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(self.dep_enrollment.depenrollmentcustomview_set.count(), 1)
        decv = self.dep_enrollment.depenrollmentcustomview_set.first()
        self.assertEqual(decv.custom_view, cv)
        self.assertEqual(decv.weight, 17)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "mdm.depenrollmentcustomview",
                 "pk": str(decv.pk),
                 "new_value": {
                     "pk": str(decv.pk),
                     "dep_enrollment": {"name": self.dep_enrollment.name,
                                        "pk": self.dep_enrollment.pk,
                                        "uuid": str(self.dep_enrollment.uuid)},
                     "custom_view": {"pk": str(cv.pk),
                                     "name": cv.name},
                     "weight": 17,
                     "created_at": decv.created_at,
                     "updated_at": decv.updated_at,
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_dep_enrollment_custom_view": [str(decv.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # update DEP enrollment custom view

    def test_update_dep_enrollment_custom_view_redirect(self):
        decv = force_dep_enrollment_custom_view(self.dep_enrollment)
        self._login_redirect(reverse("mdm:update_dep_enrollment_custom_view", args=(self.dep_enrollment.pk, decv.pk)))

    def test_update_dep_enrollment_custom_view_permission_denied(self):
        decv = force_dep_enrollment_custom_view(self.dep_enrollment)
        self._login()
        response = self.client.get(reverse("mdm:update_dep_enrollment_custom_view",
                                           args=(self.dep_enrollment.pk, decv.pk)))
        self.assertEqual(response.status_code, 403)

    def test_update_dep_enrollment_custom_view_get(self):
        decv = force_dep_enrollment_custom_view(self.dep_enrollment)
        self._login("mdm.change_depenrollmentcustomview")
        response = self.client.get(reverse("mdm:update_dep_enrollment_custom_view",
                                           args=(self.dep_enrollment.pk, decv.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollmentcustomview_form.html")
        self.assertContains(response, "Update custom view")

    def test_update_dep_enrollment_custom_view_same_custom_view_error(self):
        self._login("mdm.change_depenrollmentcustomview")
        decv = force_dep_enrollment_custom_view(self.dep_enrollment)
        decv2 = force_dep_enrollment_custom_view(self.dep_enrollment, weight=2)
        response = self.client.post(reverse("mdm:update_dep_enrollment_custom_view",
                                            args=(self.dep_enrollment.pk, decv.pk)),
                                    {"custom_view": decv2.custom_view.pk,
                                     "weight": 10},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollmentcustomview_form.html")
        self.assertFormError(response.context["form"], "custom_view",
                             "Select a valid choice. That choice is not one of the available choices.")

    def test_update_dep_enrollment_custom_view_same_weight_error(self):
        self._login("mdm.change_depenrollmentcustomview")
        decv = force_dep_enrollment_custom_view(self.dep_enrollment)
        decv2 = force_dep_enrollment_custom_view(self.dep_enrollment, weight=2)
        response = self.client.post(reverse("mdm:update_dep_enrollment_custom_view",
                                            args=(self.dep_enrollment.pk, decv.pk)),
                                    {"custom_view": decv.custom_view.pk,
                                     "weight": decv2.weight},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollmentcustomview_form.html")
        self.assertFormError(response.context["form"], "weight", "A custom view with this weight already exists.")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_dep_enrollment_custom_view(self, post_event):
        self._login("mdm.change_depenrollmentcustomview", "mdm.view_depenrollment")
        decv = force_dep_enrollment_custom_view(self.dep_enrollment)
        prev_value = decv.serialize_for_event()
        cv = force_enrollment_custom_view()
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:update_dep_enrollment_custom_view",
                                                args=(self.dep_enrollment.pk, decv.pk)),
                                        {"custom_view": cv.pk,
                                         "weight": 42},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_detail.html")
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(self.dep_enrollment.depenrollmentcustomview_set.count(), 1)
        decv2 = self.dep_enrollment.depenrollmentcustomview_set.first()
        self.assertEqual(decv2, decv)
        self.assertEqual(decv2.custom_view, cv)
        self.assertEqual(decv2.weight, 42)
        event = post_event.call_args_list[0].args[0]
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "mdm.depenrollmentcustomview",
                 "pk": str(decv2.pk),
                 "new_value": {
                     "pk": str(decv2.pk),
                     "dep_enrollment": {"name": self.dep_enrollment.name,
                                        "pk": self.dep_enrollment.pk,
                                        "uuid": str(self.dep_enrollment.uuid)},
                     "custom_view": {"pk": str(cv.pk),
                                     "name": cv.name},
                     "weight": 42,
                     "created_at": decv2.created_at,
                     "updated_at": decv2.updated_at,
                 },
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_dep_enrollment_custom_view": [str(decv2.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # delete DEP enrollment custom view

    def test_delete_dep_enrollment_custom_view_redirect(self):
        decv = force_dep_enrollment_custom_view(self.dep_enrollment)
        self._login_redirect(reverse("mdm:delete_dep_enrollment_custom_view", args=(self.dep_enrollment.pk, decv.pk)))

    def test_delete_dep_enrollment_custom_view_permission_denied(self):
        decv = force_dep_enrollment_custom_view(self.dep_enrollment)
        self._login()
        response = self.client.get(reverse("mdm:delete_dep_enrollment_custom_view",
                                           args=(self.dep_enrollment.pk, decv.pk)))
        self.assertEqual(response.status_code, 403)

    def test_delete_dep_enrollment_custom_view_get(self):
        decv = force_dep_enrollment_custom_view(self.dep_enrollment)
        self._login("mdm.delete_depenrollmentcustomview")
        response = self.client.get(reverse("mdm:delete_dep_enrollment_custom_view",
                                           args=(self.dep_enrollment.pk, decv.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollmentcustomview_confirm_delete.html")
        self.assertContains(response, "Delete custom view")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_dep_enrollment_custom_view(self, post_event):
        decv = force_dep_enrollment_custom_view(self.dep_enrollment)
        decv_pk = decv.pk
        self._login("mdm.delete_depenrollmentcustomview", "mdm.view_depenrollment")
        prev_value = decv.serialize_for_event()
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:delete_dep_enrollment_custom_view",
                                                args=(self.dep_enrollment.pk, decv.pk)),
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_detail.html")
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(self.dep_enrollment.depenrollmentcustomview_set.count(), 0)
        event = post_event.call_args_list[0].args[0]
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "mdm.depenrollmentcustomview",
                 "pk": str(decv_pk),
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_dep_enrollment_custom_view": [str(decv_pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

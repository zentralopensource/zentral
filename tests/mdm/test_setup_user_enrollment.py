from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.inventory.models import MetaBusinessUnit
from .utils import force_push_certificate, force_scep_config, force_user_enrollment


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MDMUserEnrollmentSetupViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()

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

    # create User enrollment

    def test_create_user_enrollment_redirect(self):
        self._login_redirect(reverse("mdm:create_user_enrollment"))

    def test_create_user_enrollment_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:create_user_enrollment"))
        self.assertEqual(response.status_code, 403)

    def test_create_user_enrollment_get(self):
        self._login("mdm.add_userenrollment")
        response = self.client.get(reverse("mdm:create_user_enrollment"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/userenrollment_form.html")
        self.assertContains(response, "Create user enrollment")

    def test_create_user_enrollment_post(self):
        self._login("mdm.add_userenrollment", "mdm.view_userenrollment")
        name = get_random_string(64)
        push_certificate = force_push_certificate()
        scep_config = force_scep_config()
        response = self.client.post(reverse("mdm:create_user_enrollment"),
                                    {"ue-name": name,
                                     "ue-scep_config": scep_config.pk,
                                     "ue-scep_verification": "",
                                     "ue-push_certificate": push_certificate.pk,
                                     "es-meta_business_unit": self.mbu.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/userenrollment_detail.html")
        self.assertContains(response, name)
        self.assertContains(response, push_certificate.name)
        self.assertContains(response, scep_config.name)
        self.assertContains(response, "without CSR verification")
        enrollment = response.context["object"]
        self.assertEqual(enrollment.name, name)
        self.assertEqual(enrollment.push_certificate, push_certificate)
        self.assertEqual(enrollment.scep_config, scep_config)

    # view User enrollment

    def test_view_user_enrollment_redirect(self):
        enrollment = force_user_enrollment(self.mbu, None)
        self._login_redirect(reverse("mdm:user_enrollment", args=(enrollment.pk,)))

    def test_view_user_enrollment_permission_denied(self):
        enrollment = force_user_enrollment(self.mbu, None)
        self._login()
        response = self.client.get(reverse("mdm:user_enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_view_user_enrollment_no_extra_perms(self):
        enrollment = force_user_enrollment(self.mbu, None)
        self._login("mdm.view_userenrollment")
        response = self.client.get(reverse("mdm:user_enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/userenrollment_detail.html")
        self.assertContains(response, enrollment.name)
        self.assertContains(response, enrollment.push_certificate.name)
        self.assertNotContains(response, enrollment.push_certificate.get_absolute_url())
        self.assertContains(response, enrollment.scep_config.name)
        self.assertNotContains(response, enrollment.scep_config.get_absolute_url())

    def test_view_user_enrollment_extra_perms(self):
        enrollment = force_user_enrollment(self.mbu, None)
        self._login("mdm.view_userenrollment", "mdm.view_pushcertificate", "mdm.view_scepconfig")
        response = self.client.get(reverse("mdm:user_enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/userenrollment_detail.html")
        self.assertContains(response, enrollment.name)
        self.assertContains(response, enrollment.push_certificate.name)
        self.assertContains(response, enrollment.push_certificate.get_absolute_url())
        self.assertContains(response, enrollment.scep_config.name)
        self.assertContains(response, enrollment.scep_config.get_absolute_url())

    # update User enrollment

    def test_update_user_enrollment_redirect(self):
        enrollment = force_user_enrollment(self.mbu, None)
        self._login_redirect(reverse("mdm:update_user_enrollment", args=(enrollment.pk,)))

    def test_update_user_enrollment_permission_denied(self):
        enrollment = force_user_enrollment(self.mbu, None)
        self._login()
        response = self.client.get(reverse("mdm:update_user_enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_user_enrollment_get(self):
        enrollment = force_user_enrollment(self.mbu, None)
        self._login("mdm.change_userenrollment")
        response = self.client.get(reverse("mdm:update_user_enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/userenrollment_form.html")
        self.assertContains(response, f"[USER] {enrollment.name}")

    def test_update_user_enrollment_post(self):
        enrollment = force_user_enrollment(self.mbu, None)
        self._login("mdm.change_userenrollment", "mdm.view_userenrollment")
        new_name = get_random_string(64)
        response = self.client.post(reverse("mdm:update_user_enrollment", args=(enrollment.pk,)),
                                    {"ue-name": new_name,
                                     "ue-scep_config": enrollment.scep_config.pk,
                                     "ue-scep_verification": "on",
                                     "ue-push_certificate": enrollment.push_certificate.pk,
                                     "es-meta_business_unit": self.mbu.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/userenrollment_detail.html")
        self.assertContains(response, new_name)
        self.assertContains(response, enrollment.push_certificate.name)
        self.assertContains(response, enrollment.scep_config.name)
        self.assertContains(response, "with CSR verification")
        enrollment = response.context["object"]
        self.assertEqual(enrollment.name, new_name)

    # list User enrollments

    def test_list_user_enrollments_redirect(self):
        self._login_redirect(reverse("mdm:enrollments"))

    def test_list_user_enrollments_no_perm_empty(self):
        enrollment = force_user_enrollment(self.mbu, None)
        self._login()
        response = self.client.get(reverse("mdm:enrollments"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "1 User enrollment")
        self.assertNotContains(response, enrollment.name)

    def test_list_user_enrollments(self):
        enrollment = force_user_enrollment(self.mbu, None)
        self._login("mdm.view_userenrollment")
        response = self.client.get(reverse("mdm:enrollments"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "1 User enrollment")
        self.assertContains(response, enrollment.name)

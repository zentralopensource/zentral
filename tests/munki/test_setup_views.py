from functools import reduce
import json
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.munki.models import Enrollment
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MunkiSetupViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string())
        cls.group = Group.objects.create(name=get_random_string())
        cls.user.groups.set([cls.group])
        # mbu
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
        cls.mbu.create_enrollment_business_unit()

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

    def _post_as_json(self, url_name, data):
        return self.client.post(reverse("munki:{}".format(url_name)),
                                json.dumps(data),
                                content_type="application/json")

    def _force_enrollment(self):
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=self.mbu)
        return Enrollment.objects.create(secret=enrollment_secret)

    # enrollments

    def test_enrollments_redirect(self):
        self._login_redirect(reverse("munki:enrollment_list"))

    def test_enrollments_permission_denied(self):
        self._login()
        response = self.client.get(reverse("munki:enrollment_list"))
        self.assertEqual(response.status_code, 403)

    # create enrollment

    def test_create_enrollment_redirect(self):
        self._login_redirect(reverse("munki:create_enrollment"))

    def test_create_enrollment_permission_denied(self):
        self._login()
        response = self.client.get(reverse("munki:create_enrollment"))
        self.assertEqual(response.status_code, 403)

    def test_create_enrollment_get(self):
        self._login("munki.add_enrollment")
        response = self.client.get(reverse("munki:create_enrollment"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/enrollment_form.html")
        self.assertContains(response, "Munki enrollment")

    def test_create_enrollment_post(self):
        self._login("munki.add_enrollment", "munki.view_enrollment")
        response = self.client.post(reverse("munki:create_enrollment"),
                                    {"secret-meta_business_unit": self.mbu.pk}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/enrollment_list.html")
        enrollment = response.context["object_list"][0]
        self.assertEqual(enrollment.secret.meta_business_unit, self.mbu)
        self.assertContains(response, enrollment.secret.meta_business_unit.name)

    # enrollment package

    def test_enrollment_package_redirect(self):
        enrollment = self._force_enrollment()
        self._login_redirect(reverse("munki:enrollment_package", args=(enrollment.pk,)))

    def test_enrollment_package_permission_denied(self):
        enrollment = self._force_enrollment()
        self._login()
        response = self.client.get(reverse("munki:enrollment_package", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_enrollment_package(self):
        enrollment = self._force_enrollment()
        self._login("munki.view_enrollment")
        response = self.client.get(reverse("munki:enrollment_package", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "application/octet-stream")
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="zentral_munki_enroll.pkg"')

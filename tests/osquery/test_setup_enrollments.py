from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from accounts.models import User
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.osquery.models import Configuration, Enrollment


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class OsquerySetupEnrollmentsViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string())
        cls.group = Group.objects.create(name=get_random_string())
        cls.user.groups.set([cls.group])
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string())
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

    def _force_configuration(self):
        return Configuration.objects.create(name=get_random_string())

    def _force_enrollment(self):
        configuration = self._force_configuration()
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=self.mbu)
        return Enrollment.objects.create(configuration=configuration, secret=enrollment_secret)

    # create enrollment

    def test_create_enrollment_redirect(self):
        configuration = self._force_configuration()
        self._login_redirect(reverse("osquery:create_enrollment", args=(configuration.pk,)))

    def test_create_enrollment_permission_denied(self):
        configuration = self._force_configuration()
        self._login()
        response = self.client.get(reverse("osquery:create_enrollment", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.contrib.osquery.forms.get_osquery_versions")
    def test_create_enrollment_view_get(self, get_osquery_versions):
        get_osquery_versions.returns = {}
        self._login("osquery.add_enrollment")
        configuration = self._force_configuration()
        response = self.client.get(reverse("osquery:create_enrollment", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/enrollment_form.html")
        self.assertContains(response, "Create enrollment")
        self.assertContains(response, configuration.name)
        get_osquery_versions.assert_called_once_with()

    @patch("zentral.contrib.osquery.forms.get_osquery_versions")
    def test_create_enrollment_view_post(self, get_osquery_versions):
        get_osquery_versions.returns = {}
        self._login("osquery.add_enrollment", "osquery.view_configuration", "osquery.view_enrollment")
        configuration = self._force_configuration()
        response = self.client.post(reverse("osquery:create_enrollment", args=(configuration.pk,)),
                                    {"secret-meta_business_unit": self.mbu.pk,
                                     "configuration": configuration.pk,
                                     "osquery_release": ""}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/configuration_detail.html")
        self.assertEqual(response.context["object"], configuration)
        enrollment = response.context["enrollments"][0]
        self.assertEqual(enrollment.version, 1)
        self.assertContains(response, enrollment.secret.meta_business_unit.name)
        for view_name in ("enrollment_package", "enrollment_script", "enrollment_powershell_script"):
            self.assertContains(response, reverse(f"osquery:{view_name}", args=(configuration.pk, enrollment.pk)))
        get_osquery_versions.assert_called_once_with()

    # enrollment package

    def test_enrollment_package_redirect(self):
        enrollment = self._force_enrollment()
        self._login_redirect(reverse("osquery:enrollment_package", args=(enrollment.configuration.pk, enrollment.pk)))

    def test_enrollment_package_permission_denied(self):
        enrollment = self._force_enrollment()
        self._login()
        response = self.client.get(reverse("osquery:enrollment_package",
                                           args=(enrollment.configuration.pk, enrollment.pk)))
        self.assertEqual(response.status_code, 403)

    def test_enrollment_package(self):
        enrollment = self._force_enrollment()
        self._login("osquery.view_enrollment")
        response = self.client.get(reverse("osquery:enrollment_package",
                                           args=(enrollment.configuration.pk, enrollment.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "application/octet-stream")
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="zentral_osquery_enroll.pkg"')

    # enrollment script

    def test_enrollment_script_redirect(self):
        enrollment = self._force_enrollment()
        self._login_redirect(reverse("osquery:enrollment_script", args=(enrollment.configuration.pk, enrollment.pk)))

    def test_enrollment_script_permission_denied(self):
        enrollment = self._force_enrollment()
        self._login()
        response = self.client.get(reverse("osquery:enrollment_script",
                                           args=(enrollment.configuration.pk, enrollment.pk)))
        self.assertEqual(response.status_code, 403)

    def test_enrollment_script(self):
        enrollment = self._force_enrollment()
        self._login("osquery.view_enrollment")
        response = self.client.get(reverse("osquery:enrollment_script",
                                           args=(enrollment.configuration.pk, enrollment.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "text/x-shellscript")
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="zentral_osquery_setup.sh"')

    # enrollment powershell script

    def test_enrollment_powershell_script_redirect(self):
        enrollment = self._force_enrollment()
        self._login_redirect(reverse("osquery:enrollment_powershell_script",
                                     args=(enrollment.configuration.pk, enrollment.pk)))

    def test_enrollment_powershell_script_permission_denied(self):
        enrollment = self._force_enrollment()
        self._login()
        response = self.client.get(reverse("osquery:enrollment_powershell_script",
                                           args=(enrollment.configuration.pk, enrollment.pk)))
        self.assertEqual(response.status_code, 403)

    def test_enrollment_powershell_script(self):
        enrollment = self._force_enrollment()
        self._login("osquery.view_enrollment")
        response = self.client.get(reverse("osquery:enrollment_powershell_script",
                                           args=(enrollment.configuration.pk, enrollment.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "text/plain")
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="zentral_osquery_setup.ps1"')

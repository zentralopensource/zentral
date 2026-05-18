from unittest.mock import patch
from django.contrib.auth.models import Group
from django.contrib.contenttypes.models import ContentType
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase

from accounts.models import User
from tests.zentral_test_utils.login_case import LoginCase
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.osquery.models import Configuration, Enrollment


class OsquerySetupEnrollmentsViewsTestCase(TestCase, LoginCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "osquery"

    # utiliy methods

    def _force_configuration(self):
        return Configuration.objects.create(name=get_random_string(12))

    def _force_enrollment(self):
        configuration = self._force_configuration()
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=self.mbu)
        return Enrollment.objects.create(configuration=configuration, secret=enrollment_secret)

    # create enrollment

    def test_create_enrollment_redirect(self):
        configuration = self._force_configuration()
        self.login_redirect("create_enrollment", configuration.pk)

    def test_create_enrollment_permission_denied(self):
        configuration = self._force_configuration()
        self.login()
        response = self.client.get(reverse("osquery:create_enrollment", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.contrib.osquery.forms.get_osquery_versions")
    def test_create_enrollment_view_get(self, get_osquery_versions):
        get_osquery_versions.returns = []
        self.login("osquery.add_enrollment")
        configuration = self._force_configuration()
        response = self.client.get(reverse("osquery:create_enrollment", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/enrollment_form.html")
        self.assertContains(response, "Create enrollment")
        self.assertContains(response, configuration.name)
        get_osquery_versions.assert_called_once_with()

    @patch("zentral.contrib.osquery.forms.get_osquery_versions")
    def test_create_enrollment_view_post(self, get_osquery_versions):
        get_osquery_versions.returns = []
        self.login("osquery.add_enrollment", "osquery.view_configuration", "osquery.view_enrollment")
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
            self.assertContains(response, reverse(f"osquery_api:{view_name}", args=(enrollment.pk,)))
        get_osquery_versions.assert_called_once_with()

    @patch("zentral.contrib.osquery.releases.requests.get")
    def test_create_enrollment_view_get_osquery_versions_error_post(self, requests_get):
        requests_get.side_effect = RuntimeError("YOLO")
        self.login("osquery.add_enrollment", "osquery.view_configuration", "osquery.view_enrollment")
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
            self.assertContains(response, reverse(f"osquery_api:{view_name}", args=(enrollment.pk,)))
        requests_get.assert_called_once()

    # bump enrollment version

    def test_bump_enrollment_version_redirect(self):
        enrollment = self._force_enrollment()
        self.login_redirect("bump_enrollment_version", enrollment.configuration.pk, enrollment.pk)

    def test_bump_enrollment_version_permission_denied(self):
        enrollment = self._force_enrollment()
        self.login()
        response = self.client.get(reverse("osquery:bump_enrollment_version",
                                           args=(enrollment.configuration.pk, enrollment.pk)))
        self.assertEqual(response.status_code, 403)

    def test_bump_enrollment_version_get(self):
        enrollment = self._force_enrollment()
        self.login("osquery.change_enrollment")
        response = self.client.get(reverse("osquery:bump_enrollment_version",
                                           args=(enrollment.configuration.pk, enrollment.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/enrollment_confirm_version_bump.html")

    def test_bump_enrollment_version_post(self):
        enrollment = self._force_enrollment()
        version = enrollment.version
        self.login("osquery.change_enrollment", "osquery.view_configuration")
        response = self.client.post(reverse("osquery:bump_enrollment_version",
                                            args=(enrollment.configuration.pk, enrollment.pk)),
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/configuration_detail.html")
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.version, version + 1)

    # delete enrollment

    def test_delete_enrollment_redirect(self):
        enrollment = self._force_enrollment()
        self.login_redirect("delete_enrollment", enrollment.configuration.pk, enrollment.pk)

    def test_delete_enrollment_permission_denied(self):
        enrollment = self._force_enrollment()
        self.login()
        response = self.client.get(reverse("osquery:delete_enrollment", args=(enrollment.configuration.pk,
                                                                              enrollment.pk)))
        self.assertEqual(response.status_code, 403)

    def test_delete_enrollment_get(self):
        enrollment = self._force_enrollment()
        self.login("osquery.delete_enrollment")
        response = self.client.get(reverse("osquery:delete_enrollment", args=(enrollment.configuration.pk,
                                                                              enrollment.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/enrollment_confirm_delete.html")
        self.assertContains(response, enrollment.configuration.name)

    def test_delete_enrollment_post(self):
        enrollment = self._force_enrollment()
        self.login("osquery.delete_enrollment", "osquery.view_configuration")
        response = self.client.post(reverse("osquery:delete_enrollment", args=(enrollment.configuration.pk,
                                                                               enrollment.pk)),
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/configuration_detail.html")
        self.assertContains(response, enrollment.configuration.name)
        ctx_configuration = response.context["configuration"]
        self.assertEqual(ctx_configuration, enrollment.configuration)
        self.assertEqual(ctx_configuration.enrollment_set.filter(pk=enrollment.pk).count(), 0)

    def test_delete_enrollment_distributor_404(self):
        enrollment = self._force_enrollment()
        enrollment.distributor_content_type = ContentType.objects.get(app_label="monolith",
                                                                      model="manifestenrollmentpackage")
        enrollment.distributor_pk = 1  # invalid, only for this test, not the reason for the 404!
        super(Enrollment, enrollment).save()  # to avoid calling the distributor callback
        self.login("osquery.delete_enrollment")
        response = self.client.get(reverse("osquery:delete_enrollment", args=(enrollment.configuration.pk,
                                                                              enrollment.pk)))
        self.assertEqual(response.status_code, 404)

from functools import reduce
import operator
import plistlib
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.crypto import verify_signed_payload
from .utils import force_ota_enrollment, force_push_certificate, force_realm, force_scep_config


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MDMOTAEnrollmentSetupViewsTestCase(TestCase):
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

    # create OTA enrollment

    def test_create_ota_enrollment_redirect(self):
        self._login_redirect(reverse("mdm:create_ota_enrollment"))

    def test_create_ota_enrollment_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:create_ota_enrollment"))
        self.assertEqual(response.status_code, 403)

    def test_create_ota_enrollment_get(self):
        self._login("mdm.add_otaenrollment")
        response = self.client.get(reverse("mdm:create_ota_enrollment"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/otaenrollment_form.html")
        self.assertContains(response, "Create OTA enrollment")

    def test_create_ota_enrollment_post(self):
        self._login("mdm.add_otaenrollment", "mdm.view_otaenrollment")
        name = get_random_string(64)
        display_name = get_random_string(12)
        push_certificate = force_push_certificate()
        scep_config = force_scep_config()
        response = self.client.post(reverse("mdm:create_ota_enrollment"),
                                    {"oe-name": name,
                                     "oe-display_name": display_name,
                                     "oe-scep_config": scep_config.pk,
                                     "oe-scep_verification": "",
                                     "oe-push_certificate": push_certificate.pk,
                                     "es-meta_business_unit": self.mbu.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/otaenrollment_detail.html")
        self.assertContains(response, name)
        self.assertContains(response, display_name)
        self.assertContains(response, push_certificate.name)
        self.assertContains(response, scep_config.name)
        self.assertContains(response, "without CSR verification")
        enrollment = response.context["object"]
        self.assertEqual(enrollment.name, name)
        self.assertEqual(enrollment.display_name, display_name)
        self.assertEqual(enrollment.push_certificate, push_certificate)
        self.assertEqual(enrollment.scep_config, scep_config)

    # view OTA enrollment

    def test_view_ota_enrollment_redirect(self):
        enrollment = force_ota_enrollment(self.mbu)
        self._login_redirect(reverse("mdm:ota_enrollment", args=(enrollment.pk,)))

    def test_view_ota_enrollment_permission_denied(self):
        enrollment = force_ota_enrollment(self.mbu)
        self._login()
        response = self.client.get(reverse("mdm:ota_enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_view_ota_enrollment_no_extra_perms(self):
        enrollment = force_ota_enrollment(self.mbu)
        self._login("mdm.view_otaenrollment")
        response = self.client.get(reverse("mdm:ota_enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/otaenrollment_detail.html")
        self.assertContains(response, enrollment.name)
        self.assertContains(response, enrollment.display_name)
        self.assertContains(response, enrollment.push_certificate.name)
        self.assertNotContains(response, enrollment.push_certificate.get_absolute_url())
        self.assertContains(response, enrollment.scep_config.name)
        self.assertNotContains(response, enrollment.scep_config.get_absolute_url())

    def test_view_ota_enrollment_extra_perms(self):
        enrollment = force_ota_enrollment(self.mbu)
        self._login("mdm.view_otaenrollment", "mdm.view_pushcertificate", "mdm.view_scepconfig")
        response = self.client.get(reverse("mdm:ota_enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/otaenrollment_detail.html")
        self.assertContains(response, enrollment.name)
        self.assertContains(response, enrollment.push_certificate.name)
        self.assertContains(response, enrollment.push_certificate.get_absolute_url())
        self.assertContains(response, enrollment.scep_config.name)
        self.assertContains(response, enrollment.scep_config.get_absolute_url())

    # download OTA profile

    def test_download_profile_service_payload_redirect(self):
        enrollment = force_ota_enrollment(self.mbu)
        self._login_redirect(reverse("mdm:download_profile_service_payload", args=(enrollment.pk,)))

    def test_download_profile_service_payload_permission_denied(self):
        enrollment = force_ota_enrollment(self.mbu)
        self._login()
        response = self.client.get(reverse("mdm:download_profile_service_payload", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_download_profile_service_payload(self):
        enrollment = force_ota_enrollment(self.mbu)
        self._login("mdm.view_otaenrollment")
        response = self.client.get(reverse("mdm:download_profile_service_payload", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/x-apple-aspen-config")
        _, profile_data = verify_signed_payload(response.content)
        profile = plistlib.loads(profile_data)
        self.assertEqual(profile["PayloadContent"]["URL"], "https://zentral/public/mdm/ota_enroll/")

    def test_download_profile_service_payload_with_realm_404(self):
        enrollment = force_ota_enrollment(self.mbu, realm=force_realm())
        self._login("mdm.view_otaenrollment")
        response = self.client.get(reverse("mdm:download_profile_service_payload", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 404)

    # update OTA enrollment

    def test_update_ota_enrollment_redirect(self):
        enrollment = force_ota_enrollment(self.mbu)
        self._login_redirect(reverse("mdm:update_ota_enrollment", args=(enrollment.pk,)))

    def test_update_ota_enrollment_permission_denied(self):
        enrollment = force_ota_enrollment(self.mbu)
        self._login()
        response = self.client.get(reverse("mdm:update_ota_enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_ota_enrollment_get(self):
        enrollment = force_ota_enrollment(self.mbu)
        self._login("mdm.change_otaenrollment")
        response = self.client.get(reverse("mdm:update_ota_enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/otaenrollment_form.html")
        self.assertContains(response, f"[OTA] {enrollment.name}")

    def test_update_ota_enrollment_post(self):
        enrollment = force_ota_enrollment(self.mbu)
        self._login("mdm.change_otaenrollment", "mdm.view_otaenrollment")
        new_name = get_random_string(64)
        new_display_name = get_random_string(12)
        response = self.client.post(reverse("mdm:update_ota_enrollment", args=(enrollment.pk,)),
                                    {"oe-name": new_name,
                                     "oe-display_name": new_display_name,
                                     "oe-scep_config": enrollment.scep_config.pk,
                                     "oe-scep_verification": "on",
                                     "oe-push_certificate": enrollment.push_certificate.pk,
                                     "es-meta_business_unit": self.mbu.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/otaenrollment_detail.html")
        self.assertContains(response, new_name)
        self.assertContains(response, new_display_name)
        self.assertContains(response, enrollment.push_certificate.name)
        self.assertContains(response, enrollment.scep_config.name)
        self.assertContains(response, "with CSR verification")
        enrollment = response.context["object"]
        self.assertEqual(enrollment.name, new_name)
        self.assertEqual(enrollment.display_name, new_display_name)

    # revoke OTA enrollment

    def test_revoke_ota_enrollment_redirect(self):
        enrollment = force_ota_enrollment(self.mbu)
        self._login_redirect(reverse("mdm:revoke_ota_enrollment", args=(enrollment.pk,)))

    def test_revoke_ota_enrollment_permission_denied(self):
        enrollment = force_ota_enrollment(self.mbu)
        self._login()
        response = self.client.get(reverse("mdm:revoke_ota_enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_revoke_ota_enrollment_ok(self):
        enrollment = force_ota_enrollment(self.mbu)
        self._login("mdm.change_otaenrollment")
        response = self.client.get(reverse("mdm:revoke_ota_enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/revoke_ota_enrollment.html")

    def test_revoke_ota_enrollment_post(self):
        enrollment = force_ota_enrollment(self.mbu)
        self.assertIsNone(enrollment.enrollment_secret.revoked_at)
        self._login("mdm.change_otaenrollment", "mdm.view_otaenrollment")
        response = self.client.post(reverse("mdm:revoke_ota_enrollment", args=(enrollment.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/otaenrollment_detail.html")
        enrollment.refresh_from_db()
        self.assertIsNotNone(enrollment.enrollment_secret.revoked_at)

    # list OTA enrollments

    def test_list_ota_enrollments_redirect(self):
        self._login_redirect(reverse("mdm:enrollments"))

    def test_list_ota_enrollments_no_perm_empty(self):
        enrollment = force_ota_enrollment(self.mbu)
        self._login()
        response = self.client.get(reverse("mdm:enrollments"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "1 OTA enrollment")
        self.assertNotContains(response, enrollment.name)

    def test_list_ota_enrollments(self):
        enrollment = force_ota_enrollment(self.mbu)
        self._login("mdm.view_otaenrollment")
        response = self.client.get(reverse("mdm:enrollments"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "OTA enrollment (1)")
        self.assertContains(response, enrollment.name)

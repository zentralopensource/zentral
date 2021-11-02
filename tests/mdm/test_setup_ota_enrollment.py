from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.mdm.models import OTAEnrollment, PushCertificate, SCEPConfig


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

    def _force_push_certificate(self):
        push_certificate = PushCertificate(
            name=get_random_string(12),
            topic=get_random_string(12),
            not_before="2000-01-01",
            not_after="2040-01-01",
            certificate=b"1",
        )
        push_certificate.set_private_key(b"2")
        push_certificate.save()
        return push_certificate

    def _force_scep_config(self):
        scep_config = SCEPConfig(
            name=get_random_string(12),
            url="https://example.com/{}".format(get_random_string(12)),
            challenge_type="STATIC",
            challenge_kwargs={"challenge": get_random_string(12)}
        )
        scep_config.set_challenge_kwargs({"challenge": get_random_string(12)})
        scep_config.save()
        return scep_config

    def _force_ota_enrollment(self):
        return OTAEnrollment.objects.create(
            push_certificate=self._force_push_certificate(),
            scep_config=self._force_scep_config(),
            name=get_random_string(12),
            enrollment_secret=EnrollmentSecret.objects.create(meta_business_unit=self.mbu)
        )

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
        push_certificate = self._force_push_certificate()
        scep_config = self._force_scep_config()
        response = self.client.post(reverse("mdm:create_ota_enrollment"),
                                    {"oe-name": name,
                                     "oe-scep_config": scep_config.pk,
                                     "oe-scep_verification": "",
                                     "oe-push_certificate": push_certificate.pk,
                                     "es-meta_business_unit": self.mbu.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/otaenrollment_detail.html")
        self.assertContains(response, name)
        self.assertContains(response, push_certificate.name)
        self.assertContains(response, scep_config.name)
        self.assertContains(response, "without CSR verification")
        enrollment = response.context["object"]
        self.assertEqual(enrollment.name, name)
        self.assertEqual(enrollment.push_certificate, push_certificate)
        self.assertEqual(enrollment.scep_config, scep_config)

    # view OTA enrollment

    def test_view_ota_enrollment_redirect(self):
        enrollment = self._force_ota_enrollment()
        self._login_redirect(reverse("mdm:ota_enrollment", args=(enrollment.pk,)))

    def test_view_ota_enrollment_permission_denied(self):
        enrollment = self._force_ota_enrollment()
        self._login()
        response = self.client.get(reverse("mdm:ota_enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_view_ota_enrollment_no_extra_perms(self):
        enrollment = self._force_ota_enrollment()
        self._login("mdm.view_otaenrollment")
        response = self.client.get(reverse("mdm:ota_enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/otaenrollment_detail.html")
        self.assertContains(response, enrollment.name)
        self.assertContains(response, enrollment.push_certificate.name)
        self.assertNotContains(response, enrollment.push_certificate.get_absolute_url())
        self.assertContains(response, enrollment.scep_config.name)
        self.assertNotContains(response, enrollment.scep_config.get_absolute_url())

    def test_view_ota_enrollment_extra_perms(self):
        enrollment = self._force_ota_enrollment()
        self._login("mdm.view_otaenrollment", "mdm.view_pushcertificate", "mdm.view_scepconfig")
        response = self.client.get(reverse("mdm:ota_enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/otaenrollment_detail.html")
        self.assertContains(response, enrollment.name)
        self.assertContains(response, enrollment.push_certificate.name)
        self.assertContains(response, enrollment.push_certificate.get_absolute_url())
        self.assertContains(response, enrollment.scep_config.name)
        self.assertContains(response, enrollment.scep_config.get_absolute_url())

    # update OTA enrollment

    def test_update_ota_enrollment_redirect(self):
        enrollment = self._force_ota_enrollment()
        self._login_redirect(reverse("mdm:update_ota_enrollment", args=(enrollment.pk,)))

    def test_update_ota_enrollment_permission_denied(self):
        enrollment = self._force_ota_enrollment()
        self._login()
        response = self.client.get(reverse("mdm:update_ota_enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_ota_enrollment_get(self):
        enrollment = self._force_ota_enrollment()
        self._login("mdm.change_otaenrollment")
        response = self.client.get(reverse("mdm:update_ota_enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/otaenrollment_form.html")
        self.assertContains(response, f"[OTA] {enrollment.name}")

    def test_update_ota_enrollment_post(self):
        enrollment = self._force_ota_enrollment()
        self._login("mdm.change_otaenrollment", "mdm.view_otaenrollment")
        new_name = get_random_string(64)
        response = self.client.post(reverse("mdm:update_ota_enrollment", args=(enrollment.pk,)),
                                    {"oe-name": new_name,
                                     "oe-scep_config": enrollment.scep_config.pk,
                                     "oe-scep_verification": "on",
                                     "oe-push_certificate": enrollment.push_certificate.pk,
                                     "es-meta_business_unit": self.mbu.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/otaenrollment_detail.html")
        self.assertContains(response, new_name)
        self.assertContains(response, enrollment.push_certificate.name)
        self.assertContains(response, enrollment.scep_config.name)
        self.assertContains(response, "with CSR verification")
        enrollment = response.context["object"]
        self.assertEqual(enrollment.name, new_name)

    # list OTA enrollments

    def test_list_ota_enrollments_redirect(self):
        self._login_redirect(reverse("mdm:enrollments"))

    def test_list_ota_enrollments_no_perm_empty(self):
        enrollment = self._force_ota_enrollment()
        self._login()
        response = self.client.get(reverse("mdm:enrollments"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "1 OTA enrollment")
        self.assertNotContains(response, enrollment.name)

    def test_list_ota_enrollments(self):
        enrollment = self._force_ota_enrollment()
        self._login("mdm.view_otaenrollment")
        response = self.client.get(reverse("mdm:enrollments"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "1 OTA enrollment")
        self.assertContains(response, enrollment.name)

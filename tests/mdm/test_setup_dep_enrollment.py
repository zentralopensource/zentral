import base64
from datetime import datetime, timedelta
from functools import reduce
import operator
from unittest.mock import Mock, patch
import uuid
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.models import DEPDevice, DEPEnrollment
from zentral.utils.passwords import build_password_hash_dict
from .utils import (force_dep_enrollment, force_dep_device, force_dep_virtual_server,
                    force_push_certificate, force_realm, force_scep_config)


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MDMDEPEnrollmentSetupViewsTestCase(TestCase):
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

    # create DEP enrollment

    def test_create_dep_enrollment_redirect(self):
        self._login_redirect(reverse("mdm:create_dep_enrollment"))

    def test_create_dep_enrollment_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:create_dep_enrollment"))
        self.assertEqual(response.status_code, 403)

    def test_create_dep_enrollment_get(self):
        self._login("mdm.add_depenrollment")
        response = self.client.get(reverse("mdm:create_dep_enrollment"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_form.html")
        self.assertContains(response, "Create DEP enrollment")

    def test_create_dep_enrollment_os_version_errors(self):
        self._login("mdm.add_depenrollment", "mdm.view_depenrollment")
        name = get_random_string(64)
        display_name = get_random_string(12)
        push_certificate = force_push_certificate()
        scep_config = force_scep_config()
        dep_virtual_server = force_dep_virtual_server()
        response = self.client.post(reverse("mdm:create_dep_enrollment"),
                                    {"de-name": name,
                                     "de-display_name": display_name,
                                     "de-scep_config": scep_config.pk,
                                     "de-push_certificate": push_certificate.pk,
                                     "de-virtual_server": dep_virtual_server.pk,
                                     "de-ios_max_version": "abc",
                                     "de-ios_min_version": "abc",
                                     "de-macos_max_version": "abc",
                                     "de-macos_min_version": "abc",
                                     "es-meta_business_unit": self.mbu.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_form.html")
        self.assertFormError(response.context["dep_enrollment_form"], "ios_max_version", "Not a valid OS version")
        self.assertFormError(response.context["dep_enrollment_form"], "ios_min_version", "Not a valid OS version")
        self.assertFormError(response.context["dep_enrollment_form"], "macos_max_version", "Not a valid OS version")
        self.assertFormError(response.context["dep_enrollment_form"], "macos_min_version", "Not a valid OS version")

    def test_create_dep_enrollment_macos_admin_info_incomplete(self):
        self._login("mdm.add_depenrollment", "mdm.view_depenrollment")
        name = get_random_string(64)
        push_certificate = force_push_certificate()
        scep_config = force_scep_config()
        dep_virtual_server = force_dep_virtual_server()
        response = self.client.post(reverse("mdm:create_dep_enrollment"),
                                    {"de-name": name,
                                     "de-scep_config": scep_config.pk,
                                     "de-push_certificate": push_certificate.pk,
                                     "de-virtual_server": dep_virtual_server.pk,
                                     "de-admin_full_name": "yolo",
                                     "de-admin_short_name": "fomo",
                                     "de-await_device_configured": "on",
                                     "es-meta_business_unit": self.mbu.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_form.html")
        self.assertFormError(response.context["dep_enrollment_form"], None, "Admin information incomplete")

    def test_create_dep_enrollment_macos_admin_info_await_device_configured_error(self):
        self._login("mdm.add_depenrollment", "mdm.view_depenrollment")
        name = get_random_string(64)
        push_certificate = force_push_certificate()
        scep_config = force_scep_config()
        dep_virtual_server = force_dep_virtual_server()
        response = self.client.post(reverse("mdm:create_dep_enrollment"),
                                    {"de-name": name,
                                     "de-scep_config": scep_config.pk,
                                     "de-push_certificate": push_certificate.pk,
                                     "de-virtual_server": dep_virtual_server.pk,
                                     "de-admin_full_name": "yolo",
                                     "de-admin_short_name": "fomo",
                                     "de-admin_password": "1234",
                                     "es-meta_business_unit": self.mbu.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_form.html")
        self.assertFormError(response.context["dep_enrollment_form"],
                             "await_device_configured",
                             "Required for the admin account setup")

    def test_create_dep_enrollment_missing_realm(self):
        self._login("mdm.add_depenrollment", "mdm.view_depenrollment")
        name = get_random_string(64)
        push_certificate = force_push_certificate()
        scep_config = force_scep_config()
        dep_virtual_server = force_dep_virtual_server()
        response = self.client.post(reverse("mdm:create_dep_enrollment"),
                                    {"de-name": name,
                                     "de-use_realm_user": "on",
                                     "de-scep_config": scep_config.pk,
                                     "de-push_certificate": push_certificate.pk,
                                     "de-virtual_server": dep_virtual_server.pk,
                                     "es-meta_business_unit": self.mbu.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_form.html")
        self.assertFormError(response.context["dep_enrollment_form"],
                             "use_realm_user",
                             "This option is only valid if a 'realm' is selected")

    def test_create_dep_enrollment_missing_username_pattern(self):
        self._login("mdm.add_depenrollment", "mdm.view_depenrollment")
        name = get_random_string(64)
        push_certificate = force_push_certificate()
        scep_config = force_scep_config()
        dep_virtual_server = force_dep_virtual_server()
        realm = force_realm()
        response = self.client.post(reverse("mdm:create_dep_enrollment"),
                                    {"de-name": name,
                                     "de-realm": realm.pk,
                                     "de-use_realm_user": "on",
                                     "de-scep_config": scep_config.pk,
                                     "de-push_certificate": push_certificate.pk,
                                     "de-virtual_server": dep_virtual_server.pk,
                                     "es-meta_business_unit": self.mbu.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_form.html")
        self.assertFormError(response.context["dep_enrollment_form"],
                             "username_pattern",
                             "This field is required when the 'use realm user' option is ticked")

    def test_create_dep_enrollment_invalid_username_pattern_choice(self):
        self._login("mdm.add_depenrollment", "mdm.view_depenrollment")
        name = get_random_string(64)
        push_certificate = force_push_certificate()
        scep_config = force_scep_config()
        dep_virtual_server = force_dep_virtual_server()
        realm = force_realm()
        response = self.client.post(reverse("mdm:create_dep_enrollment"),
                                    {"de-name": name,
                                     "de-realm": realm.pk,
                                     "de-username_pattern": "YOLO",
                                     "de-scep_config": scep_config.pk,
                                     "de-push_certificate": push_certificate.pk,
                                     "de-virtual_server": dep_virtual_server.pk,
                                     "es-meta_business_unit": self.mbu.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_form.html")
        self.assertFormError(response.context["dep_enrollment_form"],
                             "username_pattern",
                             'Select a valid choice. YOLO is not one of the available choices.')

    def test_create_dep_enrollment_username_pattern_without_use_realm_user(self):
        self._login("mdm.add_depenrollment", "mdm.view_depenrollment")
        name = get_random_string(64)
        push_certificate = force_push_certificate()
        scep_config = force_scep_config()
        dep_virtual_server = force_dep_virtual_server()
        realm = force_realm()
        response = self.client.post(reverse("mdm:create_dep_enrollment"),
                                    {"de-name": name,
                                     "de-realm": realm.pk,
                                     "de-username_pattern": DEPEnrollment.UsernamePattern.EMAIL_PREFIX,
                                     "de-scep_config": scep_config.pk,
                                     "de-push_certificate": push_certificate.pk,
                                     "de-virtual_server": dep_virtual_server.pk,
                                     "es-meta_business_unit": self.mbu.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_form.html")
        self.assertFormError(response.context["dep_enrollment_form"],
                             "username_pattern",
                             "This field can only be used if the 'use realm user' option is ticked")

    def test_create_dep_enrollment_no_token(self):
        self._login("mdm.add_depenrollment", "mdm.view_depenrollment")
        name = get_random_string(64)
        display_name = get_random_string(12)
        push_certificate = force_push_certificate()
        scep_config = force_scep_config()
        dep_virtual_server = force_dep_virtual_server()
        dep_virtual_server.token = None
        dep_virtual_server.save()
        realm = force_realm()
        response = self.client.post(reverse("mdm:create_dep_enrollment"),
                                    {"de-name": name,
                                     "de-display_name": display_name,
                                     "de-realm": realm.pk,
                                     "de-scep_config": scep_config.pk,
                                     "de-push_certificate": push_certificate.pk,
                                     "de-virtual_server": dep_virtual_server.pk,
                                     "es-meta_business_unit": self.mbu.pk,
                                     "de-is_supervised": "on"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_form.html")
        self.assertFormError(response.context["form"], None, "DEP virtual server has no token")

    def test_create_dep_enrollment_token_expired(self):
        self._login("mdm.add_depenrollment", "mdm.view_depenrollment")
        name = get_random_string(64)
        display_name = get_random_string(12)
        push_certificate = force_push_certificate()
        scep_config = force_scep_config()
        dep_virtual_server = force_dep_virtual_server()
        dep_virtual_server.token.access_token_expiry = datetime.utcnow() - timedelta(seconds=10)
        dep_virtual_server.token.save()
        realm = force_realm()
        response = self.client.post(reverse("mdm:create_dep_enrollment"),
                                    {"de-name": name,
                                     "de-display_name": display_name,
                                     "de-realm": realm.pk,
                                     "de-scep_config": scep_config.pk,
                                     "de-push_certificate": push_certificate.pk,
                                     "de-virtual_server": dep_virtual_server.pk,
                                     "es-meta_business_unit": self.mbu.pk,
                                     "de-is_supervised": "on"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_form.html")
        self.assertFormError(response.context["form"], None, "DEP virtual server token has expired")

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_virtual_server")
    def test_create_dep_enrollment_post(self, from_dep_virtual_server):
        profile_uuid = uuid.uuid4()
        client = Mock()
        client.add_profile.return_value = {
            "profile_uuid": str(profile_uuid).upper().replace("-", ""),
            "devices": {}
        }
        from_dep_virtual_server.return_value = client
        self._login("mdm.add_depenrollment", "mdm.view_depenrollment")
        name = get_random_string(64)
        display_name = get_random_string(12)
        push_certificate = force_push_certificate()
        scep_config = force_scep_config()
        dep_virtual_server = force_dep_virtual_server()
        response = self.client.post(reverse("mdm:create_dep_enrollment"),
                                    {"de-name": name,
                                     "de-display_name": display_name,
                                     "de-scep_config": scep_config.pk,
                                     "de-scep_verification": "",
                                     "de-push_certificate": push_certificate.pk,
                                     "de-virtual_server": dep_virtual_server.pk,
                                     "de-is_mdm_removable": "on",
                                     "de-is_supervised": "",
                                     "de-ios_min_version": "12.3.1",
                                     "de-macos_max_version": "15",
                                     "de-admin_full_name": "yolo",
                                     "de-admin_short_name": "fomo",
                                     "de-await_device_configured": "on",
                                     "de-admin_password": "1234",
                                     "de-ssp-Accessibility": "on",
                                     "es-meta_business_unit": self.mbu.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_detail.html")
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
        self.assertEqual(enrollment.ios_max_version, "")
        self.assertEqual(enrollment.ios_min_version, "12.3.1")
        self.assertEqual(enrollment.macos_max_version, "15")
        self.assertEqual(enrollment.macos_min_version, "")
        self.assertEqual(enrollment.skip_setup_items, ["Accessibility"])
        self.assertEqual(enrollment.admin_full_name, "yolo")
        self.assertEqual(enrollment.admin_short_name, "fomo")
        pwd_hash_data = enrollment.admin_password_hash["SALTED-SHA512-PBKDF2"]
        salt = base64.b64decode(pwd_hash_data["salt"])
        iterations = pwd_hash_data["iterations"]
        self.assertEqual(
            build_password_hash_dict("1234", iterations=iterations, salt=salt),
            enrollment.admin_password_hash
        )
        client.add_profile.assert_called_once()
        self.assertEqual(enrollment.uuid, profile_uuid)
        self.assertContains(response, "OS version &lt; 15")
        self.assertContains(response, "12.3.1 ≤ OS version")

    # view DEP enrollment

    def test_view_dep_enrollment_redirect(self):
        enrollment = force_dep_enrollment(self.mbu)
        self._login_redirect(reverse("mdm:dep_enrollment", args=(enrollment.pk,)))

    def test_view_dep_enrollment_permission_denied(self):
        enrollment = force_dep_enrollment(self.mbu)
        self._login()
        response = self.client.get(reverse("mdm:dep_enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_view_dep_enrollment_no_extra_perms(self):
        enrollment = force_dep_enrollment(self.mbu)
        self._login("mdm.view_depenrollment")
        response = self.client.get(reverse("mdm:dep_enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_detail.html")
        self.assertContains(response, enrollment.name)
        self.assertContains(response, enrollment.display_name)
        self.assertContains(response, enrollment.push_certificate.name)
        self.assertNotContains(response, enrollment.push_certificate.get_absolute_url())
        self.assertContains(response, enrollment.scep_config.name)
        self.assertNotContains(response, enrollment.scep_config.get_absolute_url())
        self.assertNotContains(response, "Username pattern")
        self.assertNotContains(response, "Username prefix without")
        self.assertNotContains(response, "Realm user is admin")

    def test_view_dep_enrollment_extra_perms(self):
        enrollment = force_dep_enrollment(self.mbu)
        self._login("mdm.view_depenrollment", "mdm.view_pushcertificate", "mdm.view_scepconfig")
        response = self.client.get(reverse("mdm:dep_enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_detail.html")
        self.assertContains(response, enrollment.name)
        self.assertContains(response, enrollment.push_certificate.name)
        self.assertContains(response, enrollment.push_certificate.get_absolute_url())
        self.assertContains(response, enrollment.scep_config.name)
        self.assertContains(response, enrollment.scep_config.get_absolute_url())

    def test_view_dep_enrollment_use_realm_user(self):
        enrollment = force_dep_enrollment(self.mbu)
        enrollment.use_realm_user = True
        enrollment.username_pattern = DEPEnrollment.UsernamePattern.DEVICE_USERNAME
        enrollment.save()
        self._login("mdm.view_depenrollment")
        response = self.client.get(reverse("mdm:dep_enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_detail.html")
        self.assertContains(response, enrollment.name)
        self.assertContains(response, "Username pattern")
        self.assertContains(response, "Username prefix without")
        self.assertContains(response, "Realm user is admin")

    # update DEP enrollment

    def test_update_dep_enrollment_redirect(self):
        enrollment = force_dep_enrollment(self.mbu)
        self._login_redirect(reverse("mdm:update_dep_enrollment", args=(enrollment.pk,)))

    def test_update_dep_enrollment_permission_denied(self):
        enrollment = force_dep_enrollment(self.mbu)
        self._login()
        response = self.client.get(reverse("mdm:update_dep_enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_dep_enrollment_get(self):
        enrollment = force_dep_enrollment(self.mbu)
        self._login("mdm.change_depenrollment")
        response = self.client.get(reverse("mdm:update_dep_enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_form.html")
        self.assertContains(response, f"[DEP] {enrollment.name}")

    def test_update_dep_enrollment_post_not_removable_only_if_supervised(self):
        enrollment = force_dep_enrollment(self.mbu)
        self._login("mdm.change_depenrollment")
        response = self.client.post(reverse("mdm:update_dep_enrollment", args=(enrollment.pk,)),
                                    {"de-name": enrollment.name,
                                     "de-scep_config": enrollment.scep_config.pk,
                                     "de-push_certificate": enrollment.push_certificate.pk,
                                     "de-virtual_server": enrollment.virtual_server.pk,
                                     "es-meta_business_unit": self.mbu.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_form.html")
        self.assertFormError(response.context["dep_enrollment_form"],
                             "is_mdm_removable",
                             "Can only be set to False if 'Is supervised' is set to True")

    def test_update_dep_enrollment_post_add_admin_only_full_name(self):
        enrollment = force_dep_enrollment(self.mbu)
        self._login("mdm.change_depenrollment")
        response = self.client.post(reverse("mdm:update_dep_enrollment", args=(enrollment.pk,)),
                                    {"de-name": enrollment.name,
                                     "de-scep_config": enrollment.scep_config.pk,
                                     "de-push_certificate": enrollment.push_certificate.pk,
                                     "de-virtual_server": enrollment.virtual_server.pk,
                                     "de-is_mdm_removable": False,
                                     "de-is_supervised": True,
                                     "de-admin_full_name": "Yolo",
                                     "es-meta_business_unit": self.mbu.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_form.html")
        self.assertFormError(response.context["dep_enrollment_form"], None, "Admin information incomplete")

    def test_update_dep_enrollment_post_add_admin_without_prev_pwd_missing_info(self):
        enrollment = force_dep_enrollment(self.mbu)
        self._login("mdm.change_depenrollment")
        response = self.client.post(reverse("mdm:update_dep_enrollment", args=(enrollment.pk,)),
                                    {"de-name": enrollment.name,
                                     "de-scep_config": enrollment.scep_config.pk,
                                     "de-push_certificate": enrollment.push_certificate.pk,
                                     "de-virtual_server": enrollment.virtual_server.pk,
                                     "de-is_mdm_removable": False,
                                     "de-is_supervised": True,
                                     "de-admin_full_name": "Yolo",
                                     "de-admin_short_name": "Fomo",
                                     "es-meta_business_unit": self.mbu.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_form.html")
        self.assertFormError(response.context["dep_enrollment_form"], None, "Admin information incomplete")

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_virtual_server")
    def test_update_dep_enrollment_post(self, from_dep_virtual_server):
        realm = force_realm()
        enrollment = force_dep_enrollment(self.mbu)
        device1 = force_dep_device(profile_status=DEPDevice.PROFILE_STATUS_ASSIGNED, enrollment=enrollment)
        self.assertFalse(device1.is_deleted())
        device2 = force_dep_device(profile_status=DEPDevice.PROFILE_STATUS_ASSIGNED, enrollment=enrollment)
        self.assertFalse(device2.is_deleted())
        profile_uuid = uuid.uuid4()
        client = Mock()
        client.add_profile.return_value = {
            "profile_uuid": str(profile_uuid).upper().replace("-", ""),
            "devices": {
                device1.serial_number: "SUCCESS",
                device2.serial_number: "NOT_ACCESSIBLE",
            }
        }
        from_dep_virtual_server.return_value = client
        self._login("mdm.change_depenrollment", "mdm.view_depenrollment")
        new_name = get_random_string(12)
        new_display_name = get_random_string(12)
        response = self.client.post(reverse("mdm:update_dep_enrollment", args=(enrollment.pk,)),
                                    {"de-name": new_name,
                                     "de-display_name": new_display_name,
                                     "de-realm": realm.pk,
                                     "de-scep_config": enrollment.scep_config.pk,
                                     "de-scep_verification": "on",
                                     "de-push_certificate": enrollment.push_certificate.pk,
                                     "de-virtual_server": enrollment.virtual_server.pk,
                                     "de-is_mdm_removable": "on",
                                     "de-is_supervised": "",
                                     "de-ssp-AppleID": "on",
                                     "de-language": "de",
                                     "de-include_tls_certificates": "on",
                                     "de-macos_min_version": "13.3.1",
                                     "de-admin_full_name": "Yolo",
                                     "de-admin_short_name": "Fomo",
                                     "de-admin_password": "123456",
                                     "de-await_device_configured": "on",
                                     "es-meta_business_unit": self.mbu.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_detail.html")
        self.assertContains(response, new_name)
        self.assertContains(response, new_display_name)
        self.assertContains(response, realm.name)
        self.assertContains(response, enrollment.push_certificate.name)
        self.assertContains(response, enrollment.scep_config.name)
        self.assertContains(response, "with CSR verification")
        enrollment = response.context["object"]
        self.assertEqual(enrollment.name, new_name)
        self.assertEqual(enrollment.display_name, new_display_name)
        self.assertEqual(enrollment.realm, realm)
        self.assertEqual(enrollment.macos_min_version, "13.3.1")
        self.assertEqual(enrollment.skip_setup_items, ["AppleID"])
        pwd_hash_data = enrollment.admin_password_hash["SALTED-SHA512-PBKDF2"]
        salt = base64.b64decode(pwd_hash_data["salt"])
        iterations = pwd_hash_data["iterations"]
        self.assertEqual(
            build_password_hash_dict("123456", iterations=iterations, salt=salt),
            enrollment.admin_password_hash
        )
        client.add_profile.assert_called_once()
        self.assertEqual(enrollment.uuid, profile_uuid)
        device1.refresh_from_db()
        self.assertFalse(device1.is_deleted())
        device2.refresh_from_db()
        self.assertTrue(device2.is_deleted())

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_virtual_server")
    def test_update_dep_enrollment_post_remove_admin(self, from_dep_virtual_server):
        realm = force_realm()
        enrollment = force_dep_enrollment(self.mbu)
        enrollment.admin_full_name = "yolo"
        enrollment.admin_short_name = "fomo"
        enrollment.admin_password_hash = build_password_hash_dict("1234")
        enrollment.save()
        profile_uuid = uuid.uuid4()
        client = Mock()
        client.add_profile.return_value = {
            "profile_uuid": str(profile_uuid).upper().replace("-", ""),
            "devices": {},
        }
        from_dep_virtual_server.return_value = client
        self._login("mdm.change_depenrollment", "mdm.view_depenrollment")
        response = self.client.post(reverse("mdm:update_dep_enrollment", args=(enrollment.pk,)),
                                    {"de-name": enrollment.name,
                                     "de-display_name": enrollment.display_name,
                                     "de-realm": realm.pk,
                                     "de-scep_config": enrollment.scep_config.pk,
                                     "de-push_certificate": enrollment.push_certificate.pk,
                                     "de-virtual_server": enrollment.virtual_server.pk,
                                     "de-is_mdm_removable": "on",
                                     "es-meta_business_unit": self.mbu.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_detail.html")
        enrollment.refresh_from_db()
        self.assertIsNone(enrollment.admin_full_name)
        self.assertIsNone(enrollment.admin_short_name)
        self.assertIsNone(enrollment.admin_password_hash)

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_virtual_server")
    def test_update_dep_enrollment_post_update_admin_keep_pwd(self, from_dep_virtual_server):
        realm = force_realm()
        enrollment = force_dep_enrollment(self.mbu)
        enrollment.admin_full_name = "yolo"
        enrollment.admin_short_name = "fomo"
        enrollment.admin_password_hash = existing_password_hash = build_password_hash_dict("1234")
        enrollment.save()
        profile_uuid = uuid.uuid4()
        client = Mock()
        client.add_profile.return_value = {
            "profile_uuid": str(profile_uuid).upper().replace("-", ""),
            "devices": {}
        }
        from_dep_virtual_server.return_value = client
        self._login("mdm.change_depenrollment", "mdm.view_depenrollment")
        response = self.client.post(reverse("mdm:update_dep_enrollment", args=(enrollment.pk,)),
                                    {"de-name": enrollment.name,
                                     "de-display_name": enrollment.display_name,
                                     "de-realm": realm.pk,
                                     "de-scep_config": enrollment.scep_config.pk,
                                     "de-push_certificate": enrollment.push_certificate.pk,
                                     "de-virtual_server": enrollment.virtual_server.pk,
                                     "de-is_mdm_removable": "on",
                                     "de-admin_full_name": "yolo2",
                                     "de-admin_short_name": "fomo2",
                                     "de-await_device_configured": "on",
                                     "es-meta_business_unit": self.mbu.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_detail.html")
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.admin_full_name, "yolo2")
        self.assertEqual(enrollment.admin_short_name, "fomo2")
        self.assertEqual(enrollment.admin_password_hash, existing_password_hash)

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_virtual_server")
    def test_update_dep_enrollment_post_update_admin_update_pwd(self, from_dep_virtual_server):
        realm = force_realm()
        enrollment = force_dep_enrollment(self.mbu)
        enrollment.admin_full_name = "yolo"
        enrollment.admin_short_name = "fomo"
        enrollment.admin_password_hash = build_password_hash_dict("1234")
        enrollment.save()
        profile_uuid = uuid.uuid4()
        client = Mock()
        client.add_profile.return_value = {
            "profile_uuid": str(profile_uuid).upper().replace("-", ""),
            "devices": {}
        }
        from_dep_virtual_server.return_value = client
        self._login("mdm.change_depenrollment", "mdm.view_depenrollment")
        response = self.client.post(reverse("mdm:update_dep_enrollment", args=(enrollment.pk,)),
                                    {"de-name": enrollment.name,
                                     "de-display_name": enrollment.display_name,
                                     "de-realm": realm.pk,
                                     "de-scep_config": enrollment.scep_config.pk,
                                     "de-push_certificate": enrollment.push_certificate.pk,
                                     "de-virtual_server": enrollment.virtual_server.pk,
                                     "de-is_mdm_removable": "on",
                                     "de-admin_full_name": "yolo2",
                                     "de-admin_short_name": "fomo2",
                                     "de-admin_password": "654321",
                                     "de-await_device_configured": "on",
                                     "es-meta_business_unit": self.mbu.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depenrollment_detail.html")
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.admin_full_name, "yolo2")
        self.assertEqual(enrollment.admin_short_name, "fomo2")
        pwd_hash_data = enrollment.admin_password_hash["SALTED-SHA512-PBKDF2"]
        salt = base64.b64decode(pwd_hash_data["salt"])
        iterations = pwd_hash_data["iterations"]
        self.assertEqual(
            build_password_hash_dict("654321", iterations=iterations, salt=salt),
            enrollment.admin_password_hash
        )

    # list DEP enrollments

    def test_list_dep_enrollments_redirect(self):
        self._login_redirect(reverse("mdm:enrollments"))

    def test_list_dep_enrollments_no_perm_empty(self):
        enrollment = force_dep_enrollment(self.mbu)
        self._login()
        response = self.client.get(reverse("mdm:enrollments"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "1 DEP enrollment")
        self.assertNotContains(response, enrollment.name)

    def test_list_dep_enrollments(self):
        enrollment = force_dep_enrollment(self.mbu)
        self._login("mdm.view_depenrollment")
        response = self.client.get(reverse("mdm:enrollments"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "DEP enrollment (1)")
        self.assertContains(response, enrollment.name)

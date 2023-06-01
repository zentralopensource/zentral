from functools import reduce
import operator
from cryptography.hazmat.primitives import serialization
from django.contrib.auth.models import Group, Permission
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.mdm.models import UserEnrollment
from .utils import force_push_certificate, force_push_certificate_material, force_scep_config


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

    def _force_user_enrollment(self):
        return UserEnrollment.objects.create(
            push_certificate=force_push_certificate(with_material=True),
            scep_config=force_scep_config(),
            name=get_random_string(12),
            enrollment_secret=EnrollmentSecret.objects.create(meta_business_unit=self.mbu)
        )

    # rewrap secret

    def test_push_certificate_rewrap_secret(self):
        push_certificate = force_push_certificate()
        private_key = push_certificate.get_private_key()
        self.assertIsNotNone(private_key)
        push_certificate.rewrap_secrets()
        self.assertEqual(push_certificate.get_private_key(), private_key)

    # add push certificate

    def test_add_push_certificate_redirect(self):
        self._login_redirect(reverse("mdm:add_push_certificate"))

    def test_add_push_certificate_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:add_push_certificate"))
        self.assertEqual(response.status_code, 403)

    def test_add_push_certificate_get(self):
        self._login("mdm.add_pushcertificate")
        response = self.client.get(reverse("mdm:add_push_certificate"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/pushcertificate_form.html")
        self.assertContains(response, "Add a MDM push certificate")

    def test_add_push_certificate_post(self):
        self._login("mdm.add_pushcertificate", "mdm.view_pushcertificate")
        name = get_random_string(12)
        topic = get_random_string(12)
        cert_pem, privkey_pem, privkey_password = force_push_certificate_material(topic)
        response = self.client.post(reverse("mdm:add_push_certificate"),
                                    {"name": name,
                                     "certificate_file": SimpleUploadedFile("cert.pem", cert_pem),
                                     "key_file": SimpleUploadedFile("key.pem", privkey_pem),
                                     "key_password": privkey_password.decode("utf-8")},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/pushcertificate_detail.html")
        self.assertContains(response, name)
        self.assertContains(response, topic)
        push_certificate = response.context["object"]
        self.assertEqual(push_certificate.name, name)
        self.assertEqual(push_certificate.topic, topic)
        self.assertEqual(
            serialization.load_pem_private_key(push_certificate.get_private_key(), None).private_numbers(),
            serialization.load_pem_private_key(privkey_pem, privkey_password).private_numbers()
        )

    # view push certificate

    def test_view_push_certificate_redirect(self):
        push_certificate = force_push_certificate()
        self._login_redirect(reverse("mdm:push_certificate", args=(push_certificate.pk,)))

    def test_view_push_certificate_permission_denied(self):
        push_certificate = force_push_certificate()
        self._login()
        response = self.client.get(reverse("mdm:push_certificate", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_view_push_certificate(self):
        topic = get_random_string(12)
        push_certificate = force_push_certificate(topic=topic, with_material=True)
        self._login("mdm.view_pushcertificate", "mdm.delete_pushcertificate")
        response = self.client.get(reverse("mdm:push_certificate", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/pushcertificate_detail.html")
        self.assertContains(response, push_certificate.name)
        self.assertContains(response, topic)
        self.assertContains(response, reverse("mdm:delete_push_certificate", args=(push_certificate.pk,)))

    def test_no_delete_push_certificate_link(self):
        enrollment = self._force_user_enrollment()
        self._login("mdm.view_pushcertificate", "mdm.delete_pushcertificate")
        response = self.client.get(reverse("mdm:push_certificate", args=(enrollment.push_certificate.pk,)))
        self.assertNotContains(response, reverse("mdm:delete_push_certificate",
                                                 args=(enrollment.push_certificate.pk,)))

    # update push certificate

    def test_update_push_certificate_redirect(self):
        push_certificate = force_push_certificate(with_material=True)
        self._login_redirect(reverse("mdm:update_push_certificate", args=(push_certificate.pk,)))

    def test_update_push_certificate_permission_denied(self):
        push_certificate = force_push_certificate(with_material=True)
        self._login()
        response = self.client.get(reverse("mdm:update_push_certificate", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_push_certificate_get(self):
        push_certificate = force_push_certificate(with_material=True)
        self._login("mdm.change_pushcertificate")
        response = self.client.get(reverse("mdm:update_push_certificate", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/pushcertificate_form.html")
        self.assertContains(response, f"Update MDM push certificate <i>{push_certificate.name}</i>")

    def test_update_push_certificate_post(self):
        topic = get_random_string(12)
        push_certificate = force_push_certificate(topic=topic)
        new_name = get_random_string(12)
        cert_pem, privkey_pem, privkey_password = force_push_certificate_material(topic)
        self._login("mdm.change_pushcertificate", "mdm.view_pushcertificate")
        response = self.client.post(reverse("mdm:update_push_certificate", args=(push_certificate.pk,)),
                                    {"name": new_name,
                                     "certificate_file": SimpleUploadedFile("cert.pem", cert_pem),
                                     "key_file": SimpleUploadedFile("key.pem", privkey_pem),
                                     "key_password": privkey_password.decode("utf-8")},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/pushcertificate_detail.html")
        self.assertContains(response, new_name)
        self.assertContains(response, topic)
        push_certificate = response.context["object"]
        self.assertEqual(push_certificate.name, new_name)
        self.assertEqual(push_certificate.topic, topic)

    # list push certificates

    def test_list_push_certificates_redirect(self):
        self._login_redirect(reverse("mdm:push_certificates"))

    def test_list_push_certificates_permission_denied(self):
        force_push_certificate(with_material=True)
        self._login()
        response = self.client.get(reverse("mdm:push_certificates"))
        self.assertEqual(response.status_code, 403)

    def test_list_push_certificates(self):
        push_certificate = force_push_certificate(with_material=True)
        self._login("mdm.view_pushcertificate")
        response = self.client.get(reverse("mdm:push_certificates"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/pushcertificate_list.html")
        self.assertContains(response, "1 MDM push certificate")
        self.assertContains(response, push_certificate.name)

    # delete push certificate

    def test_delete_push_certificate_redirect(self):
        push_certificate = force_push_certificate(with_material=True)
        self._login_redirect(reverse("mdm:delete_push_certificate", args=(push_certificate.pk,)))

    def test_delete_push_certificate_permission_denied(self):
        push_certificate = force_push_certificate(with_material=True)
        self._login()
        response = self.client.get(reverse("mdm:delete_push_certificate", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_push_certificate_get(self):
        push_certificate = force_push_certificate(with_material=True)
        self._login("mdm.delete_pushcertificate")
        response = self.client.get(reverse("mdm:delete_push_certificate", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/pushcertificate_confirm_delete.html")
        self.assertContains(response, f"Delete MDM push certificate <i>{push_certificate.name}</i>")

    def test_delete_push_certificate_post(self):
        push_certificate = force_push_certificate(with_material=True)
        self._login("mdm.delete_pushcertificate", "mdm.view_pushcertificate")
        response = self.client.post(reverse("mdm:delete_push_certificate", args=(push_certificate.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/pushcertificate_list.html")
        self.assertContains(response, "0 MDM push certificates")

    def test_delete_push_certificate_bad_request(self):
        enrollment = self._force_user_enrollment()
        self._login("mdm.delete_pushcertificate")
        response = self.client.post(reverse("mdm:delete_push_certificate",
                                            args=(enrollment.push_certificate.pk,)), follow=True)
        self.assertEqual(response.status_code, 400)

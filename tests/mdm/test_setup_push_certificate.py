from functools import reduce
import operator
from unittest.mock import Mock, patch
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
from .utils import force_push_certificate, force_push_certificate_material, force_scep_issuer


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
            scep_issuer=force_scep_issuer(),
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

    # upload push certificate

    def test_upload_push_certificate_redirect(self):
        self._login_redirect(reverse("mdm:upload_push_certificate"))

    def test_upload_push_certificate_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:upload_push_certificate"))
        self.assertEqual(response.status_code, 403)

    def test_upload_push_certificate_get(self):
        self._login("mdm.add_pushcertificate")
        response = self.client.get(reverse("mdm:upload_push_certificate"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/pushcertificate_form.html")
        self.assertContains(response, "Upload MDM push certificate and key")

    def test_upload_push_certificate_post(self):
        self._login("mdm.add_pushcertificate", "mdm.view_pushcertificate")
        name = get_random_string(12)
        topic = get_random_string(12)
        cert_pem, privkey_pem, privkey_password = force_push_certificate_material(topic)
        response = self.client.post(reverse("mdm:upload_push_certificate"),
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

    # create push certificate

    def test_create_push_certificate_redirect(self):
        self._login_redirect(reverse("mdm:create_push_certificate"))

    def test_create_push_certificate_permission_denied(self):
        self._login("mdm.view_pushcertificate")
        response = self.client.get(reverse("mdm:create_push_certificate"))
        self.assertEqual(response.status_code, 403)

    def test_create_push_certificate_get(self):
        self._login("mdm.add_pushcertificate")
        response = self.client.get(reverse("mdm:create_push_certificate"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/pushcertificate_form.html")
        self.assertContains(response, "Create MDM push certificate")

    def test_create_push_certificate_name_collision(self):
        push_certificate = force_push_certificate()
        self._login("mdm.add_pushcertificate")
        response = self.client.post(reverse("mdm:create_push_certificate"),
                                    {"name": push_certificate.name})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/pushcertificate_form.html")
        self.assertFormError(response.context["form"], "name", "Push certificate with this Name already exists.")

    def test_create_push_certificate_name_post(self):
        self._login("mdm.add_pushcertificate", "mdm.view_pushcertificate")
        name = get_random_string(12)
        response = self.client.post(reverse("mdm:create_push_certificate"),
                                    {"name": name},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/pushcertificate_detail.html")
        push_certificate = response.context["object"]
        self.assertEqual(push_certificate.name, name)
        self.assertIsNotNone(push_certificate.private_key)
        self.assertIsNone(push_certificate.certificate)

    # view push certificate

    def test_view_push_certificate_redirect(self):
        push_certificate = force_push_certificate()
        self._login_redirect(reverse("mdm:push_certificate", args=(push_certificate.pk,)))

    def test_view_push_certificate_permission_denied(self):
        push_certificate = force_push_certificate()
        self._login()
        response = self.client.get(reverse("mdm:push_certificate", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_view_push_certificate_signer(self):
        topic = get_random_string(12)
        push_certificate = force_push_certificate(topic=topic, with_material=True)
        self._login("mdm.view_pushcertificate",
                    "mdm.change_pushcertificate",
                    "mdm.delete_pushcertificate")
        response = self.client.get(reverse("mdm:push_certificate", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/pushcertificate_detail.html")
        self.assertContains(response, push_certificate.name)
        self.assertContains(response, topic)
        self.assertContains(response, reverse("mdm:delete_push_certificate", args=(push_certificate.pk,)))
        self.assertNotContains(response, reverse("mdm:push_certificate_csr", args=(push_certificate.pk,)))
        self.assertContains(response, reverse("mdm:push_certificate_signed_csr", args=(push_certificate.pk,)))
        self.assertContains(response, reverse("mdm:renew_push_certificate", args=(push_certificate.pk,)))
        self.assertContains(response, reverse("mdm:upload_push_certificate_certificate", args=(push_certificate.pk,)))

    def test_view_provisioned_push_certificate_signer(self):
        topic = get_random_string(12)
        push_certificate = force_push_certificate(topic=topic, with_material=True, provisioning_uid="YoLoFoMo")
        self._login("mdm.view_pushcertificate",
                    "mdm.change_pushcertificate",
                    "mdm.delete_pushcertificate")
        response = self.client.get(reverse("mdm:push_certificate", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/pushcertificate_detail.html")
        self.assertContains(response, push_certificate.name)
        self.assertContains(response, topic)
        self.assertNotContains(response, reverse("mdm:delete_push_certificate", args=(push_certificate.pk,)))
        self.assertNotContains(response, reverse("mdm:push_certificate_csr", args=(push_certificate.pk,)))
        self.assertContains(response, reverse("mdm:push_certificate_signed_csr", args=(push_certificate.pk,)))
        self.assertContains(response, reverse("mdm:renew_push_certificate", args=(push_certificate.pk,)))
        self.assertContains(response, reverse("mdm:upload_push_certificate_certificate", args=(push_certificate.pk,)))

    @patch("zentral.contrib.mdm.views.setup.push_csr_signer", False)
    def test_view_push_certificate_no_signer(self):
        topic = get_random_string(12)
        push_certificate = force_push_certificate(topic=topic, with_material=True)
        self._login("mdm.view_pushcertificate",
                    "mdm.change_pushcertificate",
                    "mdm.delete_pushcertificate")
        response = self.client.get(reverse("mdm:push_certificate", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/pushcertificate_detail.html")
        self.assertContains(response, reverse("mdm:delete_push_certificate", args=(push_certificate.pk,)))
        self.assertContains(response, reverse("mdm:push_certificate_csr", args=(push_certificate.pk,)))
        self.assertNotContains(response, reverse("mdm:push_certificate_signed_csr", args=(push_certificate.pk,)))
        self.assertContains(response, reverse("mdm:renew_push_certificate", args=(push_certificate.pk,)))
        self.assertContains(response, reverse("mdm:upload_push_certificate_certificate", args=(push_certificate.pk,)))

    @patch("zentral.contrib.mdm.views.setup.push_csr_signer", False)
    def test_view_provisioned_push_certificate_no_signer(self):
        topic = get_random_string(12)
        push_certificate = force_push_certificate(topic=topic, with_material=True, provisioning_uid="YoLoFoMo")
        self._login("mdm.view_pushcertificate",
                    "mdm.change_pushcertificate",
                    "mdm.delete_pushcertificate")
        response = self.client.get(reverse("mdm:push_certificate", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/pushcertificate_detail.html")
        self.assertNotContains(response, reverse("mdm:delete_push_certificate", args=(push_certificate.pk,)))
        self.assertContains(response, reverse("mdm:push_certificate_csr", args=(push_certificate.pk,)))
        self.assertNotContains(response, reverse("mdm:push_certificate_signed_csr", args=(push_certificate.pk,)))
        self.assertContains(response, reverse("mdm:renew_push_certificate", args=(push_certificate.pk,)))
        self.assertContains(response, reverse("mdm:upload_push_certificate_certificate", args=(push_certificate.pk,)))

    def test_view_push_certificate_signer_no_links(self):
        topic = get_random_string(12)
        push_certificate = force_push_certificate(topic=topic, with_material=True)
        self._login("mdm.view_pushcertificate")
        response = self.client.get(reverse("mdm:push_certificate", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/pushcertificate_detail.html")
        self.assertNotContains(response, reverse("mdm:delete_push_certificate", args=(push_certificate.pk,)))
        self.assertNotContains(response, reverse("mdm:push_certificate_csr", args=(push_certificate.pk,)))
        self.assertNotContains(response, reverse("mdm:delete_push_certificate", args=(push_certificate.pk,)))
        self.assertNotContains(response, reverse("mdm:renew_push_certificate", args=(push_certificate.pk,)))
        self.assertNotContains(response, reverse("mdm:upload_push_certificate_certificate",
                                                 args=(push_certificate.pk,)))

    @patch("zentral.contrib.mdm.views.setup.push_csr_signer", False)
    def test_view_push_certificate_no_signer_no_links(self):
        topic = get_random_string(12)
        push_certificate = force_push_certificate(topic=topic, with_material=True)
        self._login("mdm.view_pushcertificate")
        response = self.client.get(reverse("mdm:push_certificate", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/pushcertificate_detail.html")
        self.assertNotContains(response, reverse("mdm:delete_push_certificate", args=(push_certificate.pk,)))
        self.assertNotContains(response, reverse("mdm:push_certificate_csr", args=(push_certificate.pk,)))
        self.assertNotContains(response, reverse("mdm:delete_push_certificate", args=(push_certificate.pk,)))
        self.assertNotContains(response, reverse("mdm:renew_push_certificate", args=(push_certificate.pk,)))
        self.assertNotContains(response, reverse("mdm:upload_push_certificate_certificate",
                                                 args=(push_certificate.pk,)))

    def test_no_delete_push_certificate_link(self):
        enrollment = self._force_user_enrollment()
        self._login("mdm.view_pushcertificate", "mdm.delete_pushcertificate")
        response = self.client.get(reverse("mdm:push_certificate", args=(enrollment.push_certificate.pk,)))
        self.assertNotContains(response, reverse("mdm:delete_push_certificate",
                                                 args=(enrollment.push_certificate.pk,)))

    # push certificate CSR

    def test_push_certificate_csr_redirect(self):
        push_certificate = force_push_certificate()
        self._login_redirect(reverse("mdm:push_certificate_csr", args=(push_certificate.pk,)))

    def test_push_certificate_csr_permission_denied(self):
        push_certificate = force_push_certificate()
        self._login("mdm.view_pushcertificate")
        response = self.client.get(reverse("mdm:push_certificate_csr", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_push_certificate_csr(self):
        push_certificate = force_push_certificate(with_material=True)
        self._login("mdm.change_pushcertificate")
        response = self.client.get(reverse("mdm:push_certificate_csr", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Content-Type"], "application/pkcs10")
        self.assertEqual(response.headers["Content-Disposition"],
                         f'attachment; filename="push_certificate_{push_certificate.pk}.csr"')

    # push certificate signed CSR

    def test_push_certificate_signed_csr_redirect(self):
        push_certificate = force_push_certificate()
        self._login_redirect(reverse("mdm:push_certificate_signed_csr", args=(push_certificate.pk,)))

    def test_push_certificate_signed_csr_permission_denied(self):
        push_certificate = force_push_certificate()
        self._login("mdm.view_pushcertificate")
        response = self.client.get(reverse("mdm:push_certificate_signed_csr", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.contrib.mdm.views.setup.push_csr_signer", False)
    def test_push_certificate_no_signer_404(self):
        push_certificate = force_push_certificate(with_material=True)
        self._login("mdm.change_pushcertificate")
        response = self.client.get(reverse("mdm:push_certificate_signed_csr", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 404)

    @patch("zentral.contrib.mdm.push_csr_signers.requests.post")
    @patch("zentral.contrib.mdm.push_csr_signers.make_get_caller_identity_request")
    def test_push_certificate_signed_csr(self, make_get_caller_identity_request, requests_post):
        make_get_caller_identity_request.return_value = {}
        response = Mock()
        response.json.return_value = {"signed_csr": "1234"}
        requests_post.return_value = response
        push_certificate = force_push_certificate(with_material=True)
        self._login("mdm.change_pushcertificate")
        response = self.client.get(reverse("mdm:push_certificate_signed_csr", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(b''.join(response.streaming_content), b"1234")
        self.assertEqual(response.headers["Content-Type"], "application/octet-stream")
        self.assertEqual(response.headers["Content-Disposition"],
                         f'attachment; filename="push_certificate_{push_certificate.pk}_signed_csr.b64"')
        make_get_caller_identity_request.assert_called_once()

    # upload push certificate certificate

    def test_upload_push_certificate_certificate_redirect(self):
        push_certificate = force_push_certificate()
        self._login_redirect(reverse("mdm:upload_push_certificate_certificate", args=(push_certificate.pk,)))

    def test_upload_push_certificate_certificate_permission_denied(self):
        push_certificate = force_push_certificate()
        self._login("mdm.view_pushcertificate")
        response = self.client.get(reverse("mdm:upload_push_certificate_certificate", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_upload_push_certificate_certificate_get(self):
        push_certificate = force_push_certificate()
        self._login("mdm.change_pushcertificate")
        response = self.client.get(reverse("mdm:upload_push_certificate_certificate", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/pushcertificate_form.html")
        self.assertContains(response, "Upload MDM push certificate")

    def test_upload_push_certificate_certificate_post(self):
        push_certificate = force_push_certificate()
        push_certificate.topic = None
        push_certificate.save()
        topic = get_random_string(12)
        cert_pem, privkey_pem, _ = force_push_certificate_material(topic=topic, encrypt_key=False)
        push_certificate.set_private_key(privkey_pem)
        push_certificate.save()
        self._login("mdm.change_pushcertificate", "mdm.view_pushcertificate")
        response = self.client.post(reverse("mdm:upload_push_certificate_certificate", args=(push_certificate.pk,)),
                                    {"name": push_certificate.name,
                                     "certificate_file": SimpleUploadedFile("cert.pem", cert_pem)},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/pushcertificate_detail.html")
        self.assertEqual(response.context["object"], push_certificate)
        push_certificate.refresh_from_db()
        self.assertEqual(push_certificate.topic, topic)

    def test_upload_push_certificate_certificate_cert_key_mismatch(self):
        push_certificate = force_push_certificate(with_material=True)
        cert_pem, _, _ = force_push_certificate_material(topic=push_certificate.topic, encrypt_key=False)
        self._login("mdm.change_pushcertificate", "mdm.view_pushcertificate")
        response = self.client.post(reverse("mdm:upload_push_certificate_certificate", args=(push_certificate.pk,)),
                                    {"name": push_certificate.name,
                                     "certificate_file": SimpleUploadedFile("cert.pem", cert_pem)},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/pushcertificate_form.html")
        self.assertFormError(response.context["form"], None, "The certificate and key do not form a pair")

    def test_upload_push_certificate_certificate_different_topic(self):
        push_certificate = force_push_certificate(with_material=True)
        cert_pem, _, _ = force_push_certificate_material(privkey_bytes=push_certificate.get_private_key())
        self._login("mdm.change_pushcertificate", "mdm.view_pushcertificate")
        response = self.client.post(reverse("mdm:upload_push_certificate_certificate", args=(push_certificate.pk,)),
                                    {"name": push_certificate.name,
                                     "certificate_file": SimpleUploadedFile("cert.pem", cert_pem)},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/pushcertificate_form.html")
        self.assertFormError(response.context["form"], None, "The new certificate has a different topic")

    def test_upload_push_certificate_certificate_topic_conflict(self):
        push_certificate_conflict = force_push_certificate()
        push_certificate = force_push_certificate(with_material=True)
        push_certificate.certificate = None
        push_certificate.topic = None
        push_certificate.save()
        cert_pem, _, _ = force_push_certificate_material(
            topic=push_certificate_conflict.topic,
            privkey_bytes=push_certificate.get_private_key()
        )
        self._login("mdm.change_pushcertificate", "mdm.view_pushcertificate")
        response = self.client.post(reverse("mdm:upload_push_certificate_certificate", args=(push_certificate.pk,)),
                                    {"name": push_certificate.name,
                                     "certificate_file": SimpleUploadedFile("cert.pem", cert_pem)},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/pushcertificate_form.html")
        self.assertFormError(response.context["form"], None,
                             "A difference certificate with the same topic already exists")

    # renew push certificate

    def test_renew_push_certificate_redirect(self):
        push_certificate = force_push_certificate(with_material=True)
        self._login_redirect(reverse("mdm:renew_push_certificate", args=(push_certificate.pk,)))

    def test_renew_push_certificate_permission_denied(self):
        push_certificate = force_push_certificate(with_material=True)
        self._login()
        response = self.client.get(reverse("mdm:renew_push_certificate", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_renew_push_certificate_get(self):
        push_certificate = force_push_certificate(with_material=True)
        self._login("mdm.change_pushcertificate")
        response = self.client.get(reverse("mdm:renew_push_certificate", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/pushcertificate_form.html")
        self.assertContains(response, "Renew MDM push certificate and key")

    def test_renew_push_certificate_post(self):
        topic = get_random_string(12)
        push_certificate = force_push_certificate(topic=topic)
        new_name = get_random_string(12)
        cert_pem, privkey_pem, privkey_password = force_push_certificate_material(topic)
        self._login("mdm.change_pushcertificate", "mdm.view_pushcertificate")
        response = self.client.post(reverse("mdm:renew_push_certificate", args=(push_certificate.pk,)),
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
        self.assertContains(response, "MDM push certificate (1)")
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
        self.assertContains(response, "MDM push certificates (0)")

    def test_delete_push_certificate_bad_request(self):
        enrollment = self._force_user_enrollment()
        self._login("mdm.delete_pushcertificate")
        response = self.client.post(reverse("mdm:delete_push_certificate",
                                            args=(enrollment.push_certificate.pk,)), follow=True)
        self.assertEqual(response.status_code, 400)

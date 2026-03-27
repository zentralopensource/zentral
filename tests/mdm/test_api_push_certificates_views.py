from django.contrib.auth.models import Group
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase

from accounts.models import APIToken, User
from tests.zentral_test_utils.login_case import LoginCase
from tests.zentral_test_utils.request_case import RequestCase
from .utils import force_push_certificate


class MDMPushCertificateAPIViewsTestCase(TestCase, LoginCase, RequestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True
        )
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        cls.user.groups.set([cls.group])
        _, cls.api_key = APIToken.objects.create_for_user(cls.service_account)

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "mdm_api"

    # RequestCase implementation

    def _get_api_key(self):
        return self.api_key

    # list push certificates

    def test_list_push_certificates_unauthorized(self):
        response = self.get(reverse("mdm_api:push_certificates"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_push_certificates_permission_denied(self):
        response = self.get(reverse("mdm_api:push_certificates"))
        self.assertEqual(response.status_code, 403)

    def test_list_push_certificates(self):
        self.set_permissions("mdm.view_pushcertificate")
        push_certificate = force_push_certificate(with_material=True, provisioning_uid="YoLoFoMo")
        response = self.get(reverse("mdm_api:push_certificates"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'id': push_certificate.pk,
              'provisioning_uid': "YoLoFoMo",
              'name': push_certificate.name,
              'topic': push_certificate.topic,
              'not_before': push_certificate.not_before.isoformat().split("+")[0],
              'not_after': push_certificate.not_after.isoformat().split("+")[0],
              'certificate': push_certificate.certificate.decode("ascii"),
              'created_at': push_certificate.created_at.isoformat(),
              'updated_at': push_certificate.updated_at.isoformat()}]
        )

    def test_list_push_certificates_name_filter(self):
        push_certificate = force_push_certificate()
        force_push_certificate()
        self.set_permissions("mdm.view_pushcertificate")
        response = self.get(reverse("mdm_api:push_certificates"), data={"name": push_certificate.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'id': push_certificate.pk,
              'provisioning_uid': None,
              'name': push_certificate.name,
              'topic': push_certificate.topic,
              'not_before': push_certificate.not_before.isoformat().split("+")[0],
              'not_after': push_certificate.not_after.isoformat().split("+")[0],
              'certificate': '1',
              'created_at': push_certificate.created_at.isoformat(),
              'updated_at': push_certificate.updated_at.isoformat()}]
        )

    # get push_certificate

    def test_get_push_certificate_unauthorized(self):
        push_certificate = force_push_certificate()
        response = self.get(reverse("mdm_api:push_certificate", args=(push_certificate.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_push_certificate_permission_denied(self):
        push_certificate = force_push_certificate()
        response = self.get(reverse("mdm_api:push_certificate", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_push_certificate(self):
        push_certificate = force_push_certificate()
        self.set_permissions("mdm.view_pushcertificate")
        response = self.get(reverse("mdm_api:push_certificate", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'id': push_certificate.pk,
             'provisioning_uid': None,
             'name': push_certificate.name,
             'topic': push_certificate.topic,
             'not_before': push_certificate.not_before.isoformat().split("+")[0],
             'not_after': push_certificate.not_after.isoformat().split("+")[0],
             'certificate': "1",
             'created_at': push_certificate.created_at.isoformat(),
             'updated_at': push_certificate.updated_at.isoformat()}
        )

    # create push_certificate

    def test_create_push_certificate_unauthorized(self):
        response = self.post(reverse("mdm_api:push_certificates"), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_push_certificate_permission_denied(self):
        response = self.post(reverse("mdm_api:push_certificates"), {})
        self.assertEqual(response.status_code, 403)

    def test_create_push_certificate_method_not_allowed(self):
        self.set_permissions("mdm.add_pushcertificate")
        response = self.post(reverse("mdm_api:push_certificates"), {})
        self.assertEqual(response.status_code, 405)

    # update push_certificate

    def test_update_push_certificate_unauthorized(self):
        push_certificate = force_push_certificate()
        response = self.put(reverse("mdm_api:push_certificate", args=(push_certificate.pk,)), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_push_certificate_permission_denied(self):
        push_certificate = force_push_certificate()
        response = self.put(reverse("mdm_api:push_certificate", args=(push_certificate.pk,)), {})
        self.assertEqual(response.status_code, 403)

    def test_update_push_certificate_method_not_allowed(self):
        push_certificate = force_push_certificate()
        self.set_permissions("mdm.change_pushcertificate")
        response = self.put(reverse("mdm_api:push_certificate", args=(push_certificate.pk,)), {})
        self.assertEqual(response.status_code, 405)

    # delete push_certificate

    def test_delete_push_certificate_unauthorized(self):
        push_certificate = force_push_certificate()
        response = self.delete(reverse("mdm_api:push_certificate", args=(push_certificate.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_push_certificate_permission_denied(self):
        push_certificate = force_push_certificate()
        response = self.delete(reverse("mdm_api:push_certificate", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_push_certificate_method_not_allowed(self):
        push_certificate = force_push_certificate()
        self.set_permissions("mdm.delete_pushcertificate")
        response = self.delete(reverse("mdm_api:push_certificate", args=(push_certificate.pk,)))
        self.assertEqual(response.status_code, 405)

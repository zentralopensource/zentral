from django.contrib.auth.models import Group
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase

from accounts.models import APIToken, User
from tests.zentral_test_utils.login_case import LoginCase
from tests.zentral_test_utils.request_case import RequestCase
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.wsone.models import Instance


class APIViewsTestCase(TestCase, LoginCase, RequestCase):
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
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.bu = cls.mbu.create_enrollment_business_unit()

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "wsone"

    # RequestCase implementation

    def _get_api_key(self):
        return self.api_key

    # utils

    def force_instance(self, excluded_groups_count=0):
        instance = Instance.objects.create(
            business_unit=self.bu,
            server_url="https://{}.example.com".format(get_random_string(8)),
            client_id=get_random_string(12),
            token_url="https://{}.example.com".format(get_random_string(8)),
            username=get_random_string(12),
            excluded_groups=[get_random_string(12) for i in range(excluded_groups_count)]
        )
        instance.set_api_key(get_random_string(12))
        instance.set_client_secret(get_random_string(12))
        instance.set_password(get_random_string(12))
        instance.save()
        instance.refresh_from_db()
        return instance

    # list instances

    def test_get_instances_unauthorized(self):
        response = self.get(reverse("wsone_api:instances"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_instances_token_permission_denied(self):
        response = self.get(reverse("wsone_api:instances"))
        self.assertEqual(response.status_code, 403)

    def test_get_instances_login_unauthorized(self):
        self.login()
        response = self.client.get(reverse("wsone_api:instances"))
        self.assertEqual(response.status_code, 401)

    def test_get_instances(self):
        instance = self.force_instance(excluded_groups_count=1)
        self.set_permissions("wsone.view_instance")
        response = self.get(reverse("wsone_api:instances"))
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            {'id': instance.pk,
             'business_unit': instance.business_unit.pk,
             'client_id': instance.client_id,
             'server_url': instance.server_url,
             'version': instance.version,
             "excluded_groups": [instance.excluded_groups[0]],
             'created_at': instance.created_at.isoformat(),
             'updated_at': instance.updated_at.isoformat()},
            response.json()
        )

    # get instance

    def test_get_instance_unauthorized(self):
        instance = self.force_instance()
        response = self.get(reverse("wsone_api:instance", args=(instance.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_instance_token_permission_denied(self):
        instance = self.force_instance()
        response = self.get(reverse("wsone_api:instance", args=(instance.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_instance_login_unauthorized(self):
        instance = self.force_instance()
        self.login()
        response = self.client.get(reverse("wsone_api:instance", args=(instance.pk,)))
        self.assertEqual(response.status_code, 401)

    def test_get_instance(self):
        instance = self.force_instance()
        self.set_permissions("wsone.view_instance")
        response = self.get(reverse("wsone_api:instance", args=(instance.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            {'id': instance.pk,
             'business_unit': instance.business_unit.pk,
             'client_id': instance.client_id,
             'server_url': instance.server_url,
             'version': instance.version,
             'excluded_groups': [],
             'created_at': instance.created_at.isoformat(),
             'updated_at': instance.updated_at.isoformat()},
            response.json()
        )

    # start instance sync

    def test_start_sync_unauthorized(self):
        instance = self.force_instance()
        response = self.post(reverse("wsone_api:start_instance_sync", args=(instance.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_start_sync_token_permission_denied(self):
        instance = self.force_instance()
        response = self.post(reverse("wsone_api:start_instance_sync", args=(instance.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_start_sync_login_unauthorized(self):
        instance = self.force_instance()
        self.login()
        response = self.client.post(reverse("wsone_api:start_instance_sync", args=(instance.pk,)))
        self.assertEqual(response.status_code, 401)

    def test_start_sync_wrong_method(self):
        instance = self.force_instance()
        self.set_permissions("wsone.view_instance", "inventory.change_machinesnapshot")
        response = self.get(reverse("wsone_api:start_instance_sync", args=(instance.pk,)))
        self.assertEqual(response.status_code, 405)

    def test_start_sync(self):
        instance = self.force_instance()
        self.set_permissions("wsone.view_instance", "inventory.change_machinesnapshot")
        response = self.post(reverse("wsone_api:start_instance_sync", args=(instance.pk,)))
        self.assertEqual(response.status_code, 201)

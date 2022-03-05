from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase
from rest_framework.authtoken.models import Token
from accounts.models import User
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.wsone.models import Instance


class APIViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.service_account = User.objects.create(
            username=get_random_string(),
            email="{}@zentral.io".format(get_random_string()),
            is_service_account=True
        )
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string())
        cls.group = Group.objects.create(name=get_random_string())
        cls.service_account.groups.set([cls.group])
        cls.user.groups.set([cls.group])
        Token.objects.get_or_create(user=cls.service_account)
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string())
        cls.bu = cls.mbu.create_enrollment_business_unit()

    def force_instance(self, excluded_groups_count=0):
        instance = Instance.objects.create(
            business_unit=self.bu,
            server_url="https://{}.example.com".format(get_random_string(8)),
            client_id=get_random_string(),
            token_url="https://{}.example.com".format(get_random_string(8)),
            username=get_random_string(),
            excluded_groups=[get_random_string() for i in range(excluded_groups_count)]
        )
        instance.set_api_key(get_random_string())
        instance.set_client_secret(get_random_string())
        instance.set_password(get_random_string())
        instance.save()
        instance.refresh_from_db()
        return instance

    def set_permissions(self, *permissions):
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

    def login(self, *permissions):
        self.set_permissions(*permissions)
        self.client.force_login(self.user)

    def make_request(self, url, data=None, include_token=True, method="GET"):
        kwargs = {}
        if data is not None:
            kwargs["data"] = data
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.service_account.auth_token.key}"
        if method == "POST":
            return self.client.post(url, **kwargs)
        else:
            return self.client.get(url, **kwargs)

    def get(self, url, data=None, include_token=True):
        return self.make_request(url, data, include_token, method="GET")

    def post(self, url, data=None, include_token=True):
        return self.make_request(url, data, include_token, method="POST")

    # list instances

    def test_get_instances_unauthorized(self):
        response = self.get(reverse("wsone_api:instances"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_instances_token_permission_denied(self):
        response = self.get(reverse("wsone_api:instances"))
        self.assertEqual(response.status_code, 403)

    def test_get_instances_login_permission_denied(self):
        self.login()
        response = self.client.get(reverse("wsone_api:instances"))
        self.assertEqual(response.status_code, 403)

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

    def test_get_instance_login_permission_denied(self):
        instance = self.force_instance()
        self.login()
        response = self.client.get(reverse("wsone_api:instance", args=(instance.pk,)))
        self.assertEqual(response.status_code, 403)

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

    def test_start_sync_login_permission_denied(self):
        instance = self.force_instance()
        self.login()
        response = self.client.post(reverse("wsone_api:start_instance_sync", args=(instance.pk,)))
        self.assertEqual(response.status_code, 403)

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

from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase
from accounts.models import APIToken, User
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.intune.models import Tenant
import uuid


class APIViewsTestCase(TestCase):
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
        cls.api_key = APIToken.objects.update_or_create_for_user(cls.service_account)
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.bu = cls.mbu.create_enrollment_business_unit()

    def force_tenant(self):
        tenant = Tenant.objects.create(
            business_unit=self.bu,
            name=get_random_string(12),
            description=get_random_string(30),
            tenant_id=str(uuid.uuid4()),
            client_id=str(uuid.uuid4()),
        )
        tenant.set_client_secret(get_random_string(12))
        tenant.save()
        tenant.refresh_from_db()
        return tenant

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
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        if method == "POST":
            return self.client.post(url, **kwargs)
        else:
            return self.client.get(url, **kwargs)

    def get(self, url, data=None, include_token=True):
        return self.make_request(url, data, include_token, method="GET")

    def post(self, url, data=None, include_token=True):
        return self.make_request(url, data, include_token, method="POST")

    # list tenants

    def test_get_tenants_unauthorized(self):
        response = self.get(reverse("intune_api:tenants"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_tenants_token_permission_denied(self):
        response = self.get(reverse("intune_api:tenants"))
        self.assertEqual(response.status_code, 403)

    def test_get_tenants_login_permission_denied(self):
        self.login()
        response = self.client.get(reverse("intune_api:tenants"))
        self.assertEqual(response.status_code, 403)

    def test_get_tenants(self):
        tenant = self.force_tenant()
        self.set_permissions("intune.view_tenant")
        response = self.get(reverse("intune_api:tenants"))
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            {'id': tenant.pk,
             'business_unit': tenant.business_unit.pk,
             'name': tenant.name,
             'description': tenant.description,
             'tenant_id': tenant.tenant_id,
             'client_id': str(tenant.client_id),
             'client_secret': tenant.client_secret,
             'version': tenant.version,
             'created_at': tenant.created_at.isoformat(),
             'updated_at': tenant.updated_at.isoformat()},
            response.json()
        )

    # get tenant

    def test_get_tenant_unauthorized(self):
        tenant = self.force_tenant()
        response = self.get(reverse("intune_api:tenant", args=(tenant.tenant_id,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_tenant_token_permission_denied(self):
        tenant = self.force_tenant()
        response = self.get(reverse("intune_api:tenant", args=(tenant.tenant_id,)))
        self.assertEqual(response.status_code, 403)

    def test_get_tenant_login_permission_denied(self):
        tenant = self.force_tenant()
        self.login()
        response = self.client.get(reverse("intune_api:tenant", args=(tenant.tenant_id,)))
        self.assertEqual(response.status_code, 403)

    def test_get_tenant(self):
        tenant = self.force_tenant()
        self.set_permissions("intune.view_tenant")
        response = self.get(reverse("intune_api:tenant", args=(tenant.tenant_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            {'id': tenant.pk,
             'business_unit': tenant.business_unit.pk,
             'name': tenant.name,
             'description': tenant.description,
             'tenant_id': tenant.tenant_id,
             'client_id': str(tenant.client_id),
             'client_secret': tenant.client_secret,
             'version': tenant.version,
             'created_at': tenant.created_at.isoformat(),
             'updated_at': tenant.updated_at.isoformat()},
            response.json()
        )

    # start tenant sync

    def test_start_sync_unauthorized(self):
        tenant = self.force_tenant()
        response = self.post(reverse("intune_api:start_tenant_sync", args=(tenant.tenant_id,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_start_sync_token_permission_denied(self):
        tenant = self.force_tenant()
        response = self.post(reverse("intune_api:start_tenant_sync", args=(tenant.tenant_id,)))
        self.assertEqual(response.status_code, 403)

    def test_start_sync_login_permission_denied(self):
        tenant = self.force_tenant()
        self.login()
        response = self.client.post(reverse("intune_api:start_tenant_sync", args=(tenant.tenant_id,)))
        self.assertEqual(response.status_code, 403)

    def test_start_sync_wrong_method(self):
        tenant = self.force_tenant()
        self.set_permissions("intune.view_tenant", "inventory.change_machinesnapshot")
        response = self.get(reverse("intune_api:start_tenant_sync", args=(tenant.tenant_id,)))
        self.assertEqual(response.status_code, 405)

    def test_start_sync(self):
        tenant = self.force_tenant()
        self.set_permissions("intune.view_tenant", "inventory.change_machinesnapshot")
        response = self.post(reverse("intune_api:start_tenant_sync", args=(tenant.tenant_id,)))
        self.assertEqual(response.status_code, 201)

from functools import reduce
import hashlib
import operator
import uuid
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase
from accounts.models import APIToken, User
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.intune.models import Tenant
from zentral.core.events.base import AuditEvent


class APIViewsTestCase(TestCase):
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

    def delete(self, url, include_token=True):
        kwargs = {}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.delete(url, **kwargs)

    def post_json_data(self, url, data, include_token=True):
        kwargs = {'content_type': 'application/json',
                  'data': data}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.post(url, **kwargs)

    def put_json_data(self, url, data, include_token=True):
        kwargs = {'content_type': 'application/json',
                  'data': data}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.put(url, **kwargs)

    # list tenants

    def test_get_tenants_unauthorized(self):
        response = self.get(reverse("intune_api:tenants"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_tenants_token_permission_denied(self):
        response = self.get(reverse("intune_api:tenants"))
        self.assertEqual(response.status_code, 403)

    def test_get_tenants_login_unauthorized(self):
        self.login()
        response = self.client.get(reverse("intune_api:tenants"))
        self.assertEqual(response.status_code, 401)

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
             'client_secret': tenant.get_client_secret(),
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

    def test_get_tenant_login_unauthorized(self):
        tenant = self.force_tenant()
        self.login()
        response = self.client.get(reverse("intune_api:tenant", args=(tenant.tenant_id,)))
        self.assertEqual(response.status_code, 401)

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
             'client_secret': tenant.get_client_secret(),
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

    def test_start_sync_login_unauthorized(self):
        tenant = self.force_tenant()
        self.login()
        response = self.client.post(reverse("intune_api:start_tenant_sync", args=(tenant.tenant_id,)))
        self.assertEqual(response.status_code, 401)

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

    # create tenant

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_tenant(self, post_event):
        self.set_permissions("intune.add_tenant")
        data = {
            'business_unit': self.bu.pk,
            'name': 'Tenant Name',
            'description': 'Tenant Description',
            'tenant_id': str(uuid.uuid4()),
            'client_id': str(uuid.uuid4()),
            'client_secret': get_random_string(12),  # plain secret
        }
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post_json_data(reverse('intune_api:tenants'), data)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(Tenant.objects.filter(tenant_id=data['tenant_id']).count(), 1)
        tenant = Tenant.objects.get(tenant_id=data['tenant_id'])
        self.assertEqual(
            {
                'business_unit': data['business_unit'],
                'name': data['name'],
                'description': data['description'],
                'tenant_id': data['tenant_id'],
                'client_id': data['client_id'],
                'client_secret': data['client_secret'],  # plain secret
                'id': tenant.id,
                'version': 1,
                'created_at': tenant.created_at.isoformat(),
                'updated_at': tenant.updated_at.isoformat(),
            },
            response.json()
        )
        # In the DB should be stored in a non plain way
        self.assertNotEqual(tenant.client_secret, data['client_secret'])
        self.assertEqual(tenant.get_client_secret(), data['client_secret'])
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "intune.tenant",
                 "pk": str(tenant.pk),
                 "new_value": {
                     "pk": tenant.pk,
                     "business_unit": tenant.business_unit.pk,
                     "name": data['name'],
                     "description": data['description'],
                     "tenant_id": data['tenant_id'],
                     "client_id": data['client_id'],
                     "client_secret_hash": hashlib.sha256(data['client_secret'].encode("utf-8")).hexdigest(),
                     "created_at": tenant.created_at,
                     "updated_at": tenant.updated_at,
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"intune_tenant": [str(tenant.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["intune", "zentral"])

    def test_create_tenant_unauthorized(self):
        data = {
            'business_unit': self.bu.pk,
            'name': 'Tenant Name',
            'description': 'Tenant Description',
            'tenant_id': str(uuid.uuid4()),
            'client_id': str(uuid.uuid4()),
            'client_secret': get_random_string(12),  # plain secret
        }
        self.set_permissions('intune.add_tenants')
        response = self.post_json_data(reverse('intune_api:tenants'), data, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_tenant_permission_denied(self):
        data = {
            'business_unit': self.bu.pk,
            'name': 'Tenant Name',
            'description': 'Tenant Description',
            'tenant_id': str(uuid.uuid4()),
            'client_id': str(uuid.uuid4()),
            'client_secret': get_random_string(12),  # plain secret
        }
        response = self.post_json_data(reverse('intune_api:tenants'), data)
        self.assertEqual(response.status_code, 403)

    # update tenant

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_tenant(self, post_event):
        tenant = self.force_tenant()
        prev_value = tenant.serialize_for_event()
        data = {
            'business_unit': tenant.business_unit.pk,
            'name': 'New Name',
            'description': 'New Description',
            'tenant_id': tenant.tenant_id,  # lookup_field
            'client_id': str(uuid.uuid4()),
            'client_secret': "My secret",  # plain secret
        }
        self.set_permissions('intune.change_tenant')
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put_json_data(
                reverse('intune_api:tenant', args=(tenant.tenant_id,)),
                data
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        tenant2 = Tenant.objects.first()
        self.assertEqual(tenant, tenant2)
        self.assertEqual(response.json(), {
                'id': tenant2.id,
                'business_unit': tenant2.business_unit.pk,
                'name': 'New Name',
                'description': 'New Description',
                'tenant_id': tenant2.tenant_id,
                'client_id': data['client_id'],
                'client_secret': "My secret",
                'version': 2,
                'created_at': tenant2.created_at.isoformat(),
                'updated_at': tenant2.updated_at.isoformat(),
            })
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "intune.tenant",
                 "pk": str(tenant.pk),
                 "new_value": {
                     "pk": tenant2.pk,
                     "business_unit": tenant2.business_unit.pk,
                     "name": tenant2.name,
                     "description": tenant2.description,
                     "tenant_id": tenant2.tenant_id,
                     "client_id": str(tenant2.client_id),
                     "client_secret_hash": hashlib.sha256(tenant2.get_client_secret().encode("utf-8")).hexdigest(),
                     "created_at": tenant2.created_at,
                     "updated_at": tenant2.updated_at,
                 },
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"intune_tenant": [str(tenant.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["intune", "zentral"])

    def test_update_tenant_unauthorized(self):
        tenant = self.force_tenant()
        data = {
            'description': 'Tenant Description',
        }
        self.set_permissions('intune.change_tenant')
        response = self.put_json_data(
            reverse('intune_api:tenant', args=(tenant.tenant_id,)),
            data, include_token=False
        )
        self.assertEqual(response.status_code, 401)

    def test_update_tenant_permission_denied(self):
        tenant = self.force_tenant()
        data = {
            'description': 'Tenant Description',
        }
        response = self.put_json_data(
            reverse('intune_api:tenant', args=(tenant.tenant_id,)),
            data
        )
        self.assertEqual(response.status_code, 403)

    # delete tenant

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_tenant(self, post_event):
        tenant = self.force_tenant()
        prev_value = tenant.serialize_for_event()
        self.set_permissions("intune.delete_tenant")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("intune_api:tenant", args=(tenant.tenant_id,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(len(callbacks), 1)
        no_tenant = Tenant.objects.first()
        self.assertIsNone(no_tenant)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "intune.tenant",
                 "pk": str(tenant.pk),
                 "prev_value": prev_value
             }}
        )

    def test_delete_tenant_unauthorized(self):
        tenant = self.force_tenant()
        self.set_permissions("intune.delete_tenant")
        response = self.delete(reverse("intune_api:tenant", args=(tenant.tenant_id,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_tenant_permission_denied(self):
        tenant = self.force_tenant()
        response = self.delete(reverse("intune_api:tenant", args=(tenant.tenant_id,)))
        self.assertEqual(response.status_code, 403)

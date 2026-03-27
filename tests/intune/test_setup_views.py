import hashlib
from unittest.mock import patch
import uuid

from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import User
from tests.zentral_test_utils.login_case import LoginCase
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.core.events.base import AuditEvent
from .utils import force_tenant


class IntuneViewsTestCase(TestCase, LoginCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        # mbu
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
        cls.bu = cls.mbu.create_enrollment_business_unit()

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "intune"

    # Tenants

    def test_tenants_redirect(self):
        self.login_redirect("tenants")

    def test_tenants_permission_denied(self):
        self.login()
        response = self.client.get(reverse("intune:tenants"))
        self.assertEqual(response.status_code, 403)

    def test_tenants(self):
        tenant = force_tenant(self.bu)
        self.login("intune.view_tenant")
        response = self.client.get(reverse("intune:tenants"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, tenant.name)
        self.assertTemplateUsed(response, "intune/tenant_list.html")

    # Create Tenant

    def test_create_tenant_redirect(self):
        self.login_redirect("create_tenant")

    def test_create_tenant_permission_denied(self):
        self.login()
        response = self.client.get(reverse("intune:create_tenant"))
        self.assertEqual(response.status_code, 403)

    def test_create_tenant_get(self):
        self.login("intune.add_tenant")
        response = self.client.get(reverse("intune:create_tenant"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "intune/tenant_form.html")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_tenant_post(self, post_event):
        self.login("intune.add_tenant", "intune.view_tenant")
        name = get_random_string(12)
        description = get_random_string(12)
        tenant_id = get_random_string(12)
        client_id = str(uuid.uuid4())
        client_secret = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("intune:create_tenant"),
                                        {"business_unit": self.bu.pk,
                                         "name": name,
                                         "description": description,
                                         "tenant_id": tenant_id,
                                         "client_id": client_id,
                                         "client_secret": client_secret},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "intune/tenant_detail.html")
        tenant = response.context["object"]
        self.assertContains(response, tenant.get_client_secret())
        self.assertEqual(tenant.name, name)
        self.assertEqual(tenant.description, description)
        self.assertEqual(tenant.tenant_id, tenant_id)
        self.assertEqual(str(tenant.client_id), client_id)
        self.assertEqual(tenant.get_client_secret(), client_secret)
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
                     "name": name,
                     "description": description,
                     "tenant_id": tenant.tenant_id,
                     "client_id": str(tenant.client_id),
                     "client_secret_hash": hashlib.sha256(tenant.get_client_secret().encode("utf-8")).hexdigest(),
                     "created_at": tenant.created_at,
                     "updated_at": tenant.updated_at,
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"intune_tenant": [str(tenant.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["intune", "zentral"])

    # Update Tenant

    def test_update_tenant_redirect(self):
        tenant = force_tenant(self.bu)
        self.login_redirect("update_tenant", tenant.pk)

    def test_update_tenant_permission_denied(self):
        tenant = force_tenant(self.bu)
        self.login()
        response = self.client.get(reverse("intune:update_tenant", args=(tenant.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_tenant_get(self):
        tenant = force_tenant(self.bu)
        self.login("intune.change_tenant")
        response = self.client.get(reverse("intune:update_tenant", args=(tenant.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "intune/tenant_form.html")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_tenant_post(self, post_event):
        tenant = force_tenant(self.bu)
        prev_value = tenant.serialize_for_event()
        self.login("intune.change_tenant", "intune.view_tenant")
        name = get_random_string(12)
        description = get_random_string(12)
        tenant_id = get_random_string(12)
        client_id = str(uuid.uuid4())
        client_secret = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("intune:update_tenant", args=(tenant.pk,)),
                                        {"business_unit": self.bu.pk,
                                         "name": name,
                                         "description": description,
                                         "tenant_id": tenant_id,
                                         "client_id": client_id,
                                         "client_secret": client_secret},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "intune/tenant_detail.html")
        tenant2 = response.context["object"]
        self.assertEqual(tenant2, tenant)
        self.assertEqual(tenant2.name, name)
        self.assertEqual(tenant2.description, description)
        self.assertEqual(tenant2.tenant_id, tenant_id)
        self.assertEqual(str(tenant2.client_id), client_id)
        self.assertEqual(tenant2.get_client_secret(), client_secret)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "intune.tenant",
                 "pk": str(tenant.pk),
                 "new_value": {
                     "pk": tenant.pk,
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

    # Delete Tenant

    def test_delete_tenant_redirect(self):
        tenant = force_tenant(self.bu)
        self.login_redirect("delete_tenant", tenant.pk)

    def test_delete_tenant_permission_denied(self):
        tenant = force_tenant(self.bu)
        self.login()
        response = self.client.get(reverse("intune:delete_tenant", args=(tenant.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_tenant_get(self):
        tenant = force_tenant(self.bu)
        self.login("intune.delete_tenant")
        response = self.client.get(reverse("intune:delete_tenant", args=(tenant.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "intune/tenant_confirm_delete.html")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_tenant_post(self, post_event):
        tenant = force_tenant(self.bu)
        prev_value = tenant.serialize_for_event()
        self.login("intune.delete_tenant", "intune.view_tenant")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("intune:delete_tenant", args=(tenant.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "intune/tenant_list.html")
        self.assertNotContains(response, tenant.name)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "intune.tenant",
                 "pk": str(tenant.pk),
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"intune_tenant": [str(tenant.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["intune", "zentral"])

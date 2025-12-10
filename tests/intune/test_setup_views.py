from functools import reduce
import operator
import hashlib
from unittest.mock import patch
import uuid
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.intune.models import Tenant
from zentral.core.events.base import AuditEvent


class IntuneViewsTestCase(TestCase):
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

    # utility methods

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

    def _force_tenant(self):
        tenant = Tenant.objects.create(
            business_unit=self.bu,
            name=get_random_string(12),
            description=get_random_string(30),
            tenant_id=get_random_string(12),
            client_id=str(uuid.uuid4()),
        )
        tenant.set_client_secret(get_random_string(12))
        tenant.save()
        return tenant

    # Tenants

    def test_tenants_redirect(self):
        self._login_redirect(reverse("intune:tenants"))

    def test_tenants_permission_denied(self):
        self._login()
        response = self.client.get(reverse("intune:tenants"))
        self.assertEqual(response.status_code, 403)

    def test_tenants(self):
        tenant = self._force_tenant()
        self._login("intune.view_tenant")
        response = self.client.get(reverse("intune:tenants"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, tenant.name)
        self.assertTemplateUsed(response, "intune/tenant_list.html")

    # Create Tenant

    def test_create_tenant_redirect(self):
        self._login_redirect(reverse("intune:create_tenant"))

    def test_create_tenant_permission_denied(self):
        self._login()
        response = self.client.get(reverse("intune:create_tenant"))
        self.assertEqual(response.status_code, 403)

    def test_create_tenant_get(self):
        self._login("intune.add_tenant")
        response = self.client.get(reverse("intune:create_tenant"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "intune/tenant_form.html")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_tenant_post(self, post_event):
        self._login("intune.add_tenant", "intune.view_tenant")
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
        tenant = self._force_tenant()
        self._login_redirect(reverse("intune:update_tenant", args=(tenant.pk,)))

    def test_update_tenant_permission_denied(self):
        tenant = self._force_tenant()
        self._login()
        response = self.client.get(reverse("intune:update_tenant", args=(tenant.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_tenant_get(self):
        tenant = self._force_tenant()
        self._login("intune.change_tenant")
        response = self.client.get(reverse("intune:update_tenant", args=(tenant.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "intune/tenant_form.html")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_tenant_post(self, post_event):
        tenant = self._force_tenant()
        prev_value = tenant.serialize_for_event()
        self._login("intune.change_tenant", "intune.view_tenant")
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
        tenant = self._force_tenant()
        self._login_redirect(reverse("intune:delete_tenant", args=(tenant.pk,)))

    def test_delete_tenant_permission_denied(self):
        tenant = self._force_tenant()
        self._login()
        response = self.client.get(reverse("intune:delete_tenant", args=(tenant.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_tenant_get(self):
        tenant = self._force_tenant()
        self._login("intune.delete_tenant")
        response = self.client.get(reverse("intune:delete_tenant", args=(tenant.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "intune/tenant_confirm_delete.html")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_tenant_post(self, post_event):
        tenant = self._force_tenant()
        prev_value = tenant.serialize_for_event()
        self._login("intune.delete_tenant", "intune.view_tenant")
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

from functools import reduce
import operator
from accounts.models import User
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit, Tag, Taxonomy
from zentral.core.events.base import AuditEvent


class InventorySetupViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        # mbu
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))

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

    # meta business units

    def test_meta_business_units_redirect(self):
        self._login_redirect(reverse("inventory:mbu"))

    def test_meta_business_units_permission_denied(self):
        self._login()
        response = self.client.get(reverse("inventory:mbu"))
        self.assertEqual(response.status_code, 403)

    def test_meta_business_units(self):
        self._login("inventory.view_metabusinessunit")
        response = self.client.get(reverse("inventory:mbu"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/mbu_list.html")
        self.assertContains(response, self.mbu.name)

    # create meta business unit

    def test_create_meta_business_unit_redirect(self):
        self._login_redirect(reverse("inventory:create_mbu"))

    def test_create_meta_business_unit_permission_denied(self):
        self._login()
        response = self.client.get(reverse("inventory:create_mbu"))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_meta_business_unit(self, post_event):
        self._login(
            "inventory.add_metabusinessunit",
            "inventory.view_machinesnapshot",
            "inventory.view_metabusinessunit",
        )
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("inventory:create_mbu"),
                {"name": name},
                follow=True
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "inventory/mbu_machines.html")
        self.assertContains(response, name)
        meta_business_unit = response.context["object"]
        self.assertEqual(meta_business_unit.name, name)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "inventory.metabusinessunit",
                 "pk": str(meta_business_unit.pk),
                 "new_value": {
                     "pk": meta_business_unit.pk,
                     "name": name,
                     "api_enrollment_enabled": False,
                     "created_at": meta_business_unit.created_at,
                     "updated_at": meta_business_unit.updated_at
                 }
              }}
        )
        metadata = event.metadata.serialize()
        metadata["tags"].sort()
        self.assertEqual(
            metadata,
            {'created_at': event.metadata.created_at.isoformat(),
             'id': str(event.metadata.uuid),
             'index': 0,
             'namespace': 'zentral_audit',
             'objects': {'meta_business_unit': [str(meta_business_unit.pk)]},
             'request': {'ip': '127.0.0.1',
                         'method': 'POST',
                         'path': '/inventory/business_units/create/',
                         'user': {'email': self.user.email,
                                  'id': self.user.pk,
                                  'is_remote': False,
                                  'is_service_account': False,
                                  'is_superuser': False,
                                  'session': {'is_remote': False,
                                              'mfa_authenticated': False,
                                              'token_authenticated': False,
                                              'expire_at_browser_close': False,
                                              'expiry_age': 1209600},
                                  'username': self.user.username},
                         'view': 'inventory:create_mbu'},
             'tags': ['inventory', 'zentral'],
             'type': 'zentral_audit'}
        )

    # update meta business unit

    def test_update_meta_business_unit_redirect(self):
        meta_business_unit = MetaBusinessUnit.objects.create(name=get_random_string(12))
        self._login_redirect(reverse("inventory:update_mbu", args=(meta_business_unit.pk,)))

    def test_update_meta_business_unit_permission_denied(self):
        meta_business_unit = MetaBusinessUnit.objects.create(name=get_random_string(12))
        self._login()
        response = self.client.get(reverse("inventory:update_mbu", args=(meta_business_unit.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_meta_business_unit(self, post_event):
        self._login(
            "inventory.change_metabusinessunit",
            "inventory.view_machinesnapshot",
            "inventory.view_metabusinessunit",
        )
        name = get_random_string(12)
        meta_business_unit = MetaBusinessUnit.objects.create(name=name)
        prev_updated_at = meta_business_unit.updated_at
        updated_name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("inventory:update_mbu", args=(meta_business_unit.pk,)),
                {"name": updated_name},
                follow=True
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "inventory/mbu_machines.html")
        self.assertContains(response, updated_name)
        meta_business_unit = response.context["object"]
        self.assertEqual(meta_business_unit.name, updated_name)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "inventory.metabusinessunit",
                 "pk": str(meta_business_unit.pk),
                 "prev_value": {
                     "pk": meta_business_unit.pk,
                     "name": name,
                     "api_enrollment_enabled": False,
                     "created_at": meta_business_unit.created_at,
                     "updated_at": prev_updated_at,
                 },
                 "new_value": {
                     "pk": meta_business_unit.pk,
                     "name": updated_name,
                     "api_enrollment_enabled": False,
                     "created_at": meta_business_unit.created_at,
                     "updated_at": meta_business_unit.updated_at
                 }
              }}
        )
        metadata = event.metadata.serialize()
        metadata["tags"].sort()
        self.assertEqual(
            metadata,
            {'created_at': event.metadata.created_at.isoformat(),
             'id': str(event.metadata.uuid),
             'index': 0,
             'namespace': 'zentral_audit',
             'objects': {'meta_business_unit': [str(meta_business_unit.pk)]},
             'request': {'ip': '127.0.0.1',
                         'method': 'POST',
                         'path': f'/inventory/business_units/{meta_business_unit.pk}/update/',
                         'user': {'email': self.user.email,
                                  'id': self.user.pk,
                                  'is_remote': False,
                                  'is_service_account': False,
                                  'is_superuser': False,
                                  'session': {'is_remote': False,
                                              'mfa_authenticated': False,
                                              'token_authenticated': False,
                                              'expire_at_browser_close': False,
                                              'expiry_age': 1209600},
                                  'username': self.user.username},
                         'view': 'inventory:update_mbu'},
             'tags': ['inventory', 'zentral'],
             'type': 'zentral_audit'}
        )

    def test_update_meta_business_unit_api_enrollment_update(self):
        self._login(
            "inventory.change_metabusinessunit",
            "inventory.view_machinesnapshot",
            "inventory.view_metabusinessunit",
        )
        name = get_random_string(12)
        meta_business_unit = MetaBusinessUnit.objects.create(name=name)
        self.assertFalse(meta_business_unit.api_enrollment_enabled())
        response = self.client.get(reverse("inventory:update_mbu", args=(meta_business_unit.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/edit_mbu.html")
        self.assertNotContains(response, 'disabled id="id_api_enrollment" checked')
        response = self.client.post(
                        reverse("inventory:update_mbu", args=(meta_business_unit.pk,)),
                        {"name": name, "api_enrollment": True},
                        follow=True,
                    )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/mbu_machines.html")
        self.assertTrue(meta_business_unit.api_enrollment_enabled())
        response = self.client.get(reverse("inventory:update_mbu", args=(meta_business_unit.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/edit_mbu.html")
        self.assertContains(response, 'disabled id="id_api_enrollment" checked')

    # delete meta business unit

    def test_delete_meta_business_unit_redirect(self):
        meta_business_unit = MetaBusinessUnit.objects.create(name=get_random_string(12))
        self._login_redirect(reverse("inventory:delete_mbu", args=(meta_business_unit.pk,)))

    def test_delete_meta_business_unit_permission_denied(self):
        meta_business_unit = MetaBusinessUnit.objects.create(name=get_random_string(12))
        self._login()
        response = self.client.get(reverse("inventory:delete_mbu", args=(meta_business_unit.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_meta_business_unit(self, post_event):
        meta_business_unit = MetaBusinessUnit.objects.create(name=get_random_string(12))
        prev_pk = meta_business_unit.pk
        self._login("inventory.delete_metabusinessunit", "inventory.view_metabusinessunit")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("inventory:delete_mbu", args=(meta_business_unit.pk,)),
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "inventory/mbu_list.html")
        self.assertNotContains(response, meta_business_unit.name)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "inventory.metabusinessunit",
                 "pk": str(prev_pk),
                 "prev_value": {
                     "pk": prev_pk,
                     "name": meta_business_unit.name,
                     "api_enrollment_enabled": False,
                     "created_at": meta_business_unit.created_at,
                     "updated_at": meta_business_unit.updated_at,
                 },
              }}
        )
        metadata = event.metadata.serialize()
        metadata["tags"].sort()
        self.assertEqual(
            metadata,
            {'created_at': event.metadata.created_at.isoformat(),
             'id': str(event.metadata.uuid),
             'index': 0,
             'namespace': 'zentral_audit',
             'objects': {'meta_business_unit': [str(prev_pk)]},
             'request': {'ip': '127.0.0.1',
                         'method': 'POST',
                         'path': f'/inventory/business_units/{prev_pk}/delete/',
                         'user': {'email': self.user.email,
                                  'id': self.user.pk,
                                  'is_remote': False,
                                  'is_service_account': False,
                                  'is_superuser': False,
                                  'session': {'is_remote': False,
                                              'mfa_authenticated': False,
                                              'token_authenticated': False,
                                              'expire_at_browser_close': False,
                                              'expiry_age': 1209600},
                                  'username': self.user.username},
                         'view': 'inventory:delete_mbu'},
             'tags': ['inventory', 'zentral'],
             'type': 'zentral_audit'}
        )

    # list tags

    def test_tags_redirect(self):
        self._login_redirect(reverse("inventory:tags"))

    def test_tags_permission_denied(self):
        self._login()
        response = self.client.get(reverse("inventory:tags"))
        self.assertEqual(response.status_code, 403)

    def test_tags(self):
        tag = Tag.objects.create(name=get_random_string(12))
        self._login("inventory.view_tag")
        response = self.client.get(reverse("inventory:tags"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/tag_index.html")
        self.assertContains(response, tag.name)

    # create tag

    def test_create_tag_redirect(self):
        self._login_redirect(reverse("inventory:create_tag"))

    def test_create_tag_permission_denied(self):
        self._login()
        response = self.client.get(reverse("inventory:create_tag"))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_tag(self, post_event):
        self._login(
            "inventory.add_tag",
            "inventory.view_tag",
        )
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("inventory:create_tag"),
                {"name": name, "color": "ff0000"},
                follow=True
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "inventory/tag_index.html")
        self.assertContains(response, name)
        tag = response.context["tag_list"][0]
        self.assertEqual(tag.name, name)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "inventory.tag",
                 "pk": str(tag.pk),
                 "new_value": {
                     "pk": tag.pk,
                     "name": name,
                     "slug": name.lower(),
                     "color": "ff0000",
                 }
              }}
        )
        metadata = event.metadata.serialize()
        metadata["tags"].sort()
        self.assertEqual(
            metadata,
            {'created_at': event.metadata.created_at.isoformat(),
             'id': str(event.metadata.uuid),
             'index': 0,
             'namespace': 'zentral_audit',
             'objects': {'tag': [str(tag.pk)]},
             'request': {'ip': '127.0.0.1',
                         'method': 'POST',
                         'path': '/inventory/tags/create/',
                         'user': {'email': self.user.email,
                                  'id': self.user.pk,
                                  'is_remote': False,
                                  'is_service_account': False,
                                  'is_superuser': False,
                                  'session': {'is_remote': False,
                                              'mfa_authenticated': False,
                                              'token_authenticated': False,
                                              'expire_at_browser_close': False,
                                              'expiry_age': 1209600},
                                  'username': self.user.username},
                         'view': 'inventory:create_tag'},
             'tags': ['inventory', 'zentral'],
             'type': 'zentral_audit'}
        )

    # update tag

    def test_update_tag_redirect(self):
        tag = Tag.objects.create(name=get_random_string(12))
        self._login_redirect(reverse("inventory:update_tag", args=(tag.pk,)))

    def test_update_tag_permission_denied(self):
        tag = Tag.objects.create(name=get_random_string(12))
        self._login()
        response = self.client.get(reverse("inventory:update_tag", args=(tag.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_tag(self, post_event):
        self._login(
            "inventory.change_tag",
            "inventory.view_tag",
        )
        name = get_random_string(12)
        tag = Tag.objects.create(name=name)
        updated_name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("inventory:update_tag", args=(tag.pk,)),
                {"name": updated_name, "color": "ff0000"},
                follow=True
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "inventory/tag_index.html")
        self.assertContains(response, updated_name)
        tag = response.context["tag_list"][0]
        self.assertEqual(tag.name, updated_name)
        self.assertEqual(tag.color, "ff0000")
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "inventory.tag",
                 "pk": str(tag.pk),
                 "prev_value": {
                     "pk": tag.pk,
                     "name": name,
                     "slug": name.lower(),
                     "color": "0079bf",
                 },
                 "new_value": {
                     "pk": tag.pk,
                     "name": updated_name,
                     "slug": updated_name.lower(),
                     "color": "ff0000",
                 }
              }}
        )
        metadata = event.metadata.serialize()
        metadata["tags"].sort()
        self.assertEqual(
            metadata,
            {'created_at': event.metadata.created_at.isoformat(),
             'id': str(event.metadata.uuid),
             'index': 0,
             'namespace': 'zentral_audit',
             'objects': {'tag': [str(tag.pk)]},
             'request': {'ip': '127.0.0.1',
                         'method': 'POST',
                         'path': f'/inventory/tags/{tag.pk}/update/',
                         'user': {'email': self.user.email,
                                  'id': self.user.pk,
                                  'is_remote': False,
                                  'is_service_account': False,
                                  'is_superuser': False,
                                  'session': {'is_remote': False,
                                              'mfa_authenticated': False,
                                              'token_authenticated': False,
                                              'expire_at_browser_close': False,
                                              'expiry_age': 1209600},
                                  'username': self.user.username},
                         'view': 'inventory:update_tag'},
             'tags': ['inventory', 'zentral'],
             'type': 'zentral_audit'}
        )

    # delete tag

    def test_delete_tag_redirect(self):
        tag = Tag.objects.create(name=get_random_string(12))
        self._login_redirect(reverse("inventory:delete_tag", args=(tag.pk,)))

    def test_delete_tag_permission_denied(self):
        tag = Tag.objects.create(name=get_random_string(12))
        self._login()
        response = self.client.get(reverse("inventory:delete_tag", args=(tag.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_tag(self, post_event):
        self._login(
            "inventory.delete_tag",
            "inventory.view_tag",
        )
        tag = Tag.objects.create(name=get_random_string(12))
        prev_pk = tag.pk
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("inventory:delete_tag", args=(tag.pk,)),
                follow=True
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "inventory/tag_index.html")
        self.assertNotContains(response, tag.name)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "inventory.tag",
                 "pk": str(prev_pk),
                 "prev_value": {
                     "pk": prev_pk,
                     "name": tag.name,
                     "slug": tag.name.lower(),
                     "color": tag.color,
                 },
              }}
        )
        metadata = event.metadata.serialize()
        metadata["tags"].sort()
        self.assertEqual(
            metadata,
            {'created_at': event.metadata.created_at.isoformat(),
             'id': str(event.metadata.uuid),
             'index': 0,
             'namespace': 'zentral_audit',
             'objects': {'tag': [str(prev_pk)]},
             'request': {'ip': '127.0.0.1',
                         'method': 'POST',
                         'path': f'/inventory/tags/{tag.pk}/delete/',
                         'user': {'email': self.user.email,
                                  'id': self.user.pk,
                                  'is_remote': False,
                                  'is_service_account': False,
                                  'is_superuser': False,
                                  'session': {'is_remote': False,
                                              'mfa_authenticated': False,
                                              'token_authenticated': False,
                                              'expire_at_browser_close': False,
                                              'expiry_age': 1209600},
                                  'username': self.user.username},
                         'view': 'inventory:delete_tag'},
             'tags': ['inventory', 'zentral'],
             'type': 'zentral_audit'}
        )

    # create taxonomy

    def test_create_taxonomy_redirect(self):
        self._login_redirect(reverse("inventory:create_taxonomy"))

    def test_create_taxonomy_permission_denied(self):
        self._login()
        response = self.client.get(reverse("inventory:create_taxonomy"))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_taxonomy(self, post_event):
        self._login(
            "inventory.add_taxonomy",
            "inventory.view_tag",
            "inventory.view_taxonomy",
        )
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("inventory:create_taxonomy"),
                {"name": name},
                follow=True
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "inventory/tag_index.html")
        self.assertContains(response, name)
        taxonomy = response.context["taxonomy_list"][0]
        self.assertEqual(taxonomy.name, name)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "inventory.taxonomy",
                 "pk": str(taxonomy.pk),
                 "new_value": {
                     "pk": taxonomy.pk,
                     "name": name,
                     "created_at": taxonomy.created_at,
                     "updated_at": taxonomy.updated_at
                 }
              }}
        )
        metadata = event.metadata.serialize()
        metadata["tags"].sort()
        self.assertEqual(
            metadata,
            {'created_at': event.metadata.created_at.isoformat(),
             'id': str(event.metadata.uuid),
             'index': 0,
             'namespace': 'zentral_audit',
             'objects': {'taxonomy': [str(taxonomy.pk)]},
             'request': {'ip': '127.0.0.1',
                         'method': 'POST',
                         'path': '/inventory/taxonomies/create/',
                         'user': {'email': self.user.email,
                                  'id': self.user.pk,
                                  'is_remote': False,
                                  'is_service_account': False,
                                  'is_superuser': False,
                                  'session': {'is_remote': False,
                                              'mfa_authenticated': False,
                                              'token_authenticated': False,
                                              'expire_at_browser_close': False,
                                              'expiry_age': 1209600},
                                  'username': self.user.username},
                         'view': 'inventory:create_taxonomy'},
             'tags': ['inventory', 'zentral'],
             'type': 'zentral_audit'}
        )

    # update taxonomy

    def test_update_taxonomy_redirect(self):
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        self._login_redirect(reverse("inventory:update_taxonomy", args=(taxonomy.pk,)))

    def test_update_taxonomy_permission_denied(self):
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        self._login()
        response = self.client.get(reverse("inventory:update_taxonomy", args=(taxonomy.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_taxonomy(self, post_event):
        self._login(
            "inventory.change_taxonomy",
            "inventory.view_tag",
            "inventory.view_taxonomy",
        )
        name = get_random_string(12)
        taxonomy = Taxonomy.objects.create(name=name)
        prev_updated_at = taxonomy.updated_at
        updated_name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("inventory:update_taxonomy", args=(taxonomy.pk,)),
                {"name": updated_name},
                follow=True
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "inventory/tag_index.html")
        self.assertContains(response, updated_name)
        taxonomy = response.context["taxonomy_list"][0]
        self.assertEqual(taxonomy.name, updated_name)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "inventory.taxonomy",
                 "pk": str(taxonomy.pk),
                 "prev_value": {
                     "pk": taxonomy.pk,
                     "name": name,
                     "created_at": taxonomy.created_at,
                     "updated_at": prev_updated_at,
                 },
                 "new_value": {
                     "pk": taxonomy.pk,
                     "name": updated_name,
                     "created_at": taxonomy.created_at,
                     "updated_at": taxonomy.updated_at,
                 }
              }}
        )
        metadata = event.metadata.serialize()
        metadata["tags"].sort()
        self.assertEqual(
            metadata,
            {'created_at': event.metadata.created_at.isoformat(),
             'id': str(event.metadata.uuid),
             'index': 0,
             'namespace': 'zentral_audit',
             'objects': {'taxonomy': [str(taxonomy.pk)]},
             'request': {'ip': '127.0.0.1',
                         'method': 'POST',
                         'path': f'/inventory/taxonomies/{taxonomy.pk}/update/',
                         'user': {'email': self.user.email,
                                  'id': self.user.pk,
                                  'is_remote': False,
                                  'is_service_account': False,
                                  'is_superuser': False,
                                  'session': {'is_remote': False,
                                              'mfa_authenticated': False,
                                              'token_authenticated': False,
                                              'expire_at_browser_close': False,
                                              'expiry_age': 1209600},
                                  'username': self.user.username},
                         'view': 'inventory:update_taxonomy'},
             'tags': ['inventory', 'zentral'],
             'type': 'zentral_audit'}
        )

    # delete taxonomy

    def test_delete_taxonomy_redirect(self):
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        self._login_redirect(reverse("inventory:delete_taxonomy", args=(taxonomy.pk,)))

    def test_delete_taxonomy_permission_denied(self):
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        self._login()
        response = self.client.get(reverse("inventory:delete_taxonomy", args=(taxonomy.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_taxonomy(self, post_event):
        self._login(
            "inventory.delete_taxonomy",
            "inventory.view_tag",
        )
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        prev_pk = taxonomy.pk
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("inventory:delete_taxonomy", args=(taxonomy.pk,)),
                follow=True
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "inventory/tag_index.html")
        self.assertNotContains(response, taxonomy.name)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "inventory.taxonomy",
                 "pk": str(prev_pk),
                 "prev_value": {
                     "pk": prev_pk,
                     "name": taxonomy.name,
                     "created_at": taxonomy.created_at,
                     "updated_at": taxonomy.updated_at,
                 },
              }}
        )
        metadata = event.metadata.serialize()
        metadata["tags"].sort()
        self.assertEqual(
            metadata,
            {'created_at': event.metadata.created_at.isoformat(),
             'id': str(event.metadata.uuid),
             'index': 0,
             'namespace': 'zentral_audit',
             'objects': {'taxonomy': [str(prev_pk)]},
             'request': {'ip': '127.0.0.1',
                         'method': 'POST',
                         'path': f'/inventory/taxonomies/{taxonomy.pk}/delete/',
                         'user': {'email': self.user.email,
                                  'id': self.user.pk,
                                  'is_remote': False,
                                  'is_service_account': False,
                                  'is_superuser': False,
                                  'session': {'is_remote': False,
                                              'mfa_authenticated': False,
                                              'token_authenticated': False,
                                              'expire_at_browser_close': False,
                                              'expiry_age': 1209600},
                                  'username': self.user.username},
                         'view': 'inventory:delete_taxonomy'},
             'tags': ['inventory', 'zentral'],
             'type': 'zentral_audit'}
        )

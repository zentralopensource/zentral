from django.contrib.auth.models import AnonymousUser
from django.test import TestCase

from accounts.auth_backends import ZentralBackend, ZentralBaseBackend
from accounts.models import User


class ZentralBaseBackendTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("user", "user@zentral.com")
        cls.service_account = User.objects.create_user("sa", "sa@zentral.com", is_service_account=True)
        cls.backend = ZentralBaseBackend()

    def test_user_can_authenticate(self):
        self.assertTrue(self.backend.user_can_authenticate(self.user))

    def test_sa_can_authenticate(self):
        self.assertFalse(self.backend.user_can_authenticate(self.service_account))

    def test_get_user_permissions(self):
        self.assertEqual(self.backend.get_user_permissions(self.user), set())

    async def test_aget_user_permissions(self):
        self.assertEqual(await self.backend.aget_user_permissions(self.user), set())

    def test_get_group_permissions(self):
        self.assertEqual(self.backend.get_group_permissions(self.user), set())

    async def test_aget_group_permissions(self):
        self.assertEqual(await self.backend.aget_group_permissions(self.user), set())

    def test_get_all_permissions(self):
        self.assertEqual(self.backend.get_all_permissions(self.user), set())

    async def test_aget_all_permissions(self):
        self.assertEqual(await self.backend.aget_all_permissions(self.user), set())

    def test_with_perm(self):
        self.assertEqual(self.backend.with_perm("inventory.view_machinesnapshot").count(), 0)

    def test_has_perm(self):
        self.assertFalse(self.backend.has_perm(self.user, "inventory.view_machinesnapshot"))

    async def test_ahas_perm(self):
        self.assertFalse(await self.backend.ahas_perm(self.user, "inventory.view_machinesnapshot"))

    def test_has_module_perms(self):
        self.assertFalse(self.backend.has_module_perms(self.user, "inventory"))

    async def test_ahas_module_perms(self):
        self.assertFalse(await self.backend.ahas_module_perms(self.user, "inventory"))


class ZentralBackendTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.superuser = User.objects.create_user("su", "su@zentral.com", is_superuser=True)
        cls.backend = ZentralBackend()

    def test_superuser_has_perm(self):
        self.assertTrue(self.backend.has_perm(self.superuser, "inventory.view_machinesnapshot"))

    def test_anonymous_has_perm(self):
        self.assertFalse(self.backend.has_perm(AnonymousUser(), "inventory.view_machinesnapshot"))

    def test_superuser_has_module_perms(self):
        self.assertTrue(self.backend.has_module_perms(self.superuser, "inventory"))

    def test_anonymous_has_module_perms(self):
        self.assertFalse(self.backend.has_module_perms(AnonymousUser(), "inventory"))

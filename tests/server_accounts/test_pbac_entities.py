from django.test import TestCase
from django.utils.crypto import get_random_string
from accounts.models import User
from accounts.pbac.entities import Action, Entity, Namespace, Principal, Request


class PBACEntitiesTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            get_random_string(12),
            get_random_string(12) + "zentral.com",
            is_superuser=False,
        )
        cls.superuser = User.objects.create_user(
            get_random_string(12),
            get_random_string(12) + "zentral.com",
            is_superuser=True,
        )

    # entities

    def test_namespace_repr(self):
        n = Namespace("Inventory")
        self.assertEqual(repr(n), "Namespace <Inventory>")

    def test_entity_repr(self):
        e = Entity("Machine", "12345678910", Namespace("Inventory"))
        self.assertEqual(repr(e), 'Entity <Inventory::Machine::"12345678910">')

    def test_entity_str(self):
        e = Entity("Machine", "12345678910", Namespace("Inventory"))
        self.assertEqual(str(e), 'Inventory::Machine::"12345678910"')

    # request

    def test_user_request_is_pending(self):
        p = Principal.from_user(self.user)
        n = Namespace("Inventory")
        a = Action("createMachineTag", namespace=n)
        e = Entity("Machine", "12345678910", n)
        r = Request(p, a, e)
        self.assertTrue(r.is_authorized is None)
        self.assertTrue(r.is_pending is True)
        self.assertEqual(r.get_authorized_display(), "Pending")

    def test_superuser_request_is_authorized(self):
        p = Principal.from_user(self.superuser)
        n = Namespace("Inventory")
        a = Action("createMachineTag", namespace=n)
        e = Entity("Machine", "12345678910", n)
        r = Request(p, a, e)
        self.assertTrue(r.is_authorized is True)
        self.assertTrue(r.is_pending is False)
        self.assertEqual(r.get_authorized_display(), "Authorized")

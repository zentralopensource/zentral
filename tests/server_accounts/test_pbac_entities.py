from django.test import TestCase
from django.utils.crypto import get_random_string
from accounts.models import User
from pbac.entities import Action, Entity, Namespace, Principal, Request


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
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.com".format(get_random_string(12)),
            is_service_account=True,
        )

    # Principal.from_user

    def test_user_principal_carries_is_superuser_attr(self):
        # Policies can reference principal.is_superuser; the attribute has
        # to be on the Principal for that reference to evaluate.
        p = Principal.from_user(self.user)
        self.assertEqual(p.type, "User")
        self.assertEqual(p.attrs, {"is_superuser": False})

    def test_superuser_principal_carries_is_superuser_true(self):
        p = Principal.from_user(self.superuser)
        self.assertEqual(p.type, "User")
        self.assertEqual(p.attrs, {"is_superuser": True})

    def test_service_account_principal_has_no_attrs(self):
        # is_superuser is meaningless on a ServiceAccount (the engine's
        # auth-backend logic gates it on type == "User"), so we don't
        # carry the attribute. Keeps the Principal shape aligned with the
        # schema declaration too (ServiceAccount has no attrs declared).
        p = Principal.from_user(self.service_account)
        self.assertEqual(p.type, "ServiceAccount")
        self.assertEqual(p.attrs, {})

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

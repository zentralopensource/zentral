from django.test import SimpleTestCase

from pbac.entities import Namespace
from pbac.types import (
    AppliesTo,
    AttrSpec,
    EntityType,
    ExtensionType,
    LEGACY_PERM_APPLIES_TO,
    PrincipalType,
    PrimitiveType,
    RecordOf,
    ResourceType,
    ROLE,
    SERVICE_ACCOUNT,
    SetOf,
    SYSTEM,
    USER,
)


class PrimitiveTypeTestCase(SimpleTestCase):
    def test_values_match_cedar_human_readable_spelling(self):
        self.assertEqual(PrimitiveType.BOOL.value, "Bool")
        self.assertEqual(PrimitiveType.LONG.value, "Long")
        self.assertEqual(PrimitiveType.STRING.value, "String")


class ExtensionTypeTestCase(SimpleTestCase):
    def test_values_match_cedar_lowercase_spelling(self):
        self.assertEqual(ExtensionType.DECIMAL.value, "decimal")
        self.assertEqual(ExtensionType.IPADDR.value, "ipaddr")
        self.assertEqual(ExtensionType.DATETIME.value, "datetime")
        self.assertEqual(ExtensionType.DURATION.value, "duration")


class AttrSpecCoercionTestCase(SimpleTestCase):
    def test_bool_coerces_to_BOOL(self):
        # The footgun: bool is a subclass of int. Verify we don't fall through.
        self.assertIs(AttrSpec(bool).type, PrimitiveType.BOOL)

    def test_int_coerces_to_LONG(self):
        self.assertIs(AttrSpec(int).type, PrimitiveType.LONG)

    def test_str_coerces_to_STRING(self):
        self.assertIs(AttrSpec(str).type, PrimitiveType.STRING)

    def test_primitive_type_passes_through(self):
        self.assertIs(AttrSpec(PrimitiveType.BOOL).type, PrimitiveType.BOOL)

    def test_extension_type_passes_through(self):
        self.assertIs(AttrSpec(ExtensionType.IPADDR).type, ExtensionType.IPADDR)

    def test_entity_type_passes_through(self):
        machine = ResourceType("Machine")
        self.assertIs(AttrSpec(machine).type, machine)

    def test_set_of_passes_through(self):
        s = SetOf(PrimitiveType.STRING)
        self.assertIs(AttrSpec(s).type, s)

    def test_record_of_passes_through(self):
        r = RecordOf({"name": AttrSpec(str)})
        self.assertIs(AttrSpec(r).type, r)

    def test_unknown_type_raises(self):
        with self.assertRaises(TypeError):
            AttrSpec(float)
        with self.assertRaises(TypeError):
            AttrSpec(object())

    def test_required_defaults_true(self):
        self.assertTrue(AttrSpec(str).required)
        self.assertFalse(AttrSpec(str, required=False).required)

    def test_attr_spec_is_frozen(self):
        s = AttrSpec(str)
        with self.assertRaises(Exception):
            s.required = False


class AttrSpecEqualityTestCase(SimpleTestCase):
    def test_equal_specs_compare_equal(self):
        self.assertEqual(AttrSpec(str), AttrSpec(str))
        self.assertEqual(AttrSpec(str, required=False), AttrSpec(str, required=False))

    def test_different_specs_compare_unequal(self):
        self.assertNotEqual(AttrSpec(str), AttrSpec(int))
        self.assertNotEqual(AttrSpec(str), AttrSpec(str, required=False))


class EntityTypeTestCase(SimpleTestCase):
    def test_qualified_name_without_namespace(self):
        self.assertEqual(EntityType("Machine").qualified_name, "Machine")

    def test_qualified_name_with_namespace(self):
        ns = Namespace("Inventory")
        self.assertEqual(EntityType("Machine", namespace=ns).qualified_name, "Inventory::Machine")

    def test_repr(self):
        ns = Namespace("Inventory")
        self.assertEqual(repr(EntityType("Machine", namespace=ns)), "EntityType <Inventory::Machine>")
        self.assertEqual(repr(PrincipalType("User")), "PrincipalType <User>")
        self.assertEqual(repr(ResourceType("Machine")), "ResourceType <Machine>")

    def test_parents_default_empty_tuple(self):
        self.assertEqual(EntityType("Machine").parents, ())

    def test_parents_normalised_to_tuple(self):
        parent = EntityType("MBU")
        self.assertEqual(EntityType("Machine", parents=[parent]).parents, (parent,))

    def test_attrs_default_empty_dict(self):
        self.assertEqual(EntityType("Machine").attrs, {})


class AppliesToTestCase(SimpleTestCase):
    def test_iterables_normalised_to_tuples(self):
        a = AppliesTo(principals=[USER], resources=[SYSTEM])
        self.assertEqual(a.principals, (USER,))
        self.assertEqual(a.resources, (SYSTEM,))

    def test_context_defaults_to_none(self):
        a = AppliesTo(principals=(USER,), resources=(SYSTEM,))
        self.assertIsNone(a.context)

    def test_empty_dict_context_preserved(self):
        # IR distinguishes "no context declared" (None) from "context explicitly
        # empty" ({}); renderers may emit them differently.
        a = AppliesTo(principals=(USER,), resources=(SYSTEM,), context={})
        self.assertEqual(a.context, {})

    def test_applies_to_equality(self):
        self.assertEqual(
            AppliesTo(principals=(USER,), resources=(SYSTEM,), context={}),
            AppliesTo(principals=(USER,), resources=(SYSTEM,), context={}),
        )
        self.assertNotEqual(
            AppliesTo(principals=(USER,), resources=(SYSTEM,), context={}),
            AppliesTo(principals=(USER,), resources=(SYSTEM,), context=None),
        )


class BuiltinsTestCase(SimpleTestCase):
    def test_user_has_is_superuser_attr(self):
        self.assertEqual(USER.name, "User")
        self.assertIn("is_superuser", USER.attrs)
        self.assertEqual(USER.attrs["is_superuser"].type, PrimitiveType.BOOL)

    def test_user_parents_include_role(self):
        self.assertIn(ROLE, USER.parents)

    def test_service_account_parents_include_role(self):
        self.assertEqual(SERVICE_ACCOUNT.name, "ServiceAccount")
        self.assertIn(ROLE, SERVICE_ACCOUNT.parents)

    def test_system_resource_type(self):
        self.assertIsInstance(SYSTEM, ResourceType)
        self.assertEqual(SYSTEM.name, "System")
        self.assertEqual(SYSTEM.attrs, {})

    def test_legacy_perm_applies_to(self):
        self.assertEqual(LEGACY_PERM_APPLIES_TO.principals, (USER, SERVICE_ACCOUNT))
        self.assertEqual(LEGACY_PERM_APPLIES_TO.resources, (SYSTEM,))
        self.assertEqual(LEGACY_PERM_APPLIES_TO.context, {})

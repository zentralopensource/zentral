"""Schema IR + renderer tests.

The IR generator is tested against isolated Engine() instances so the
assertions don't depend on whatever the real singleton happens to look
like. The Cedar JSON renderer is then round-tripped through cedarpy
(validate_policies) to confirm the schema is actually accepted and gives
useful errors for typos.
"""
import json

from cedarpy import validate_policies
from django.test import SimpleTestCase, TestCase

from pbac.cedar import render_schema_human, render_schema_json
from pbac.engine import ActionGroupBasename, Engine, engine
from pbac.schema import (
    ActionIR,
    AppliesToIR,
    EntityTypeIR,
    SchemaIR,
    build_schema_ir,
)
from pbac.types import (
    AppliesTo,
    AttrSpec,
    LEGACY_PERM_APPLIES_TO,
    PrincipalType,
    PrimitiveType,
    ResourceType,
    SYSTEM,
    USER,
)


# ---------------------------------------------------------------------------
# IR generator
# ---------------------------------------------------------------------------


class BuildSchemaIRTestCase(SimpleTestCase):
    def setUp(self):
        self.engine = Engine()

    def test_empty_engine_emits_global_namespace_with_builtins(self):
        ir = build_schema_ir(self.engine)
        self.assertIsInstance(ir, SchemaIR)
        # None namespace is always seeded; built-in entity types live there.
        self.assertIn(None, ir.namespaces)
        global_ns = ir.namespaces[None]
        self.assertEqual(
            set(global_ns.entity_types.keys()),
            {"Role", "User", "ServiceAccount", "System"},
        )
        # Action groups are created lazily by register_action, not by Engine().
        self.assertEqual(global_ns.actions, {})

    def test_action_groups_appear_after_action_registration(self):
        ns = self.engine.get_namespace("Inventory")
        self.engine.register_action(
            "yolo", ns,
            [ActionGroupBasename.ADMIN, ActionGroupBasename.USER, ActionGroupBasename.VIEWER],
            applies_to=LEGACY_PERM_APPLIES_TO,
        )
        ir = build_schema_ir(self.engine)
        # Global groups are prefixed "Global" so they don't shadow the
        # per-namespace ones in a Cedar schema.
        global_actions = ir.namespaces[None].actions
        self.assertEqual(
            set(global_actions.keys()),
            {"GlobalAdminActions", "GlobalUserActions", "GlobalViewerActions"},
        )
        # Per-namespace groups keep the unprefixed names.
        ns_actions = ir.namespaces["Inventory"].actions
        self.assertIn("AdminActions", ns_actions)
        self.assertIn("UserActions", ns_actions)
        self.assertIn("ViewerActions", ns_actions)
        # All action groups have applies_to=None.
        for action in (*global_actions.values(), ns_actions["AdminActions"]):
            self.assertIsNone(action.applies_to)

    def test_user_entity_type_carries_attrs_and_parents(self):
        ir = build_schema_ir(self.engine)
        user_ir = ir.namespaces[None].entity_types["User"]
        self.assertIsInstance(user_ir, EntityTypeIR)
        self.assertEqual(user_ir.namespace_id, None)
        self.assertEqual(user_ir.parents, ("Role",))
        self.assertEqual(set(user_ir.attrs.keys()), {"is_superuser"})
        self.assertEqual(user_ir.attrs["is_superuser"].type, PrimitiveType.BOOL)

    def test_concrete_action_has_applies_to_and_member_of(self):
        ns = self.engine.get_namespace("Inventory")
        machine = ResourceType("Machine", ns)
        applies_to = AppliesTo(
            principals=(USER,),
            resources=(machine, SYSTEM),
            context={"tagID": AttrSpec(int, required=False)},
        )
        self.engine.register_action(
            "createMachineTag", ns,
            [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
            applies_to=applies_to,
            legacy_perm="inventory.add_machinetag",
        )
        ir = build_schema_ir(self.engine)
        action_ir = ir.namespaces["Inventory"].actions["createMachineTag"]
        self.assertIsInstance(action_ir, ActionIR)
        self.assertEqual(action_ir.id, "createMachineTag")
        self.assertIsInstance(action_ir.applies_to, AppliesToIR)
        self.assertEqual(action_ir.applies_to.principals, ("User",))
        self.assertEqual(action_ir.applies_to.resources, ("Inventory::Machine", "System"))
        self.assertIn("tagID", action_ir.applies_to.context)
        # member_of carries both global and per-namespace groups; the engine
        # tracks both, and the IR faithfully reflects that. Filtering for the
        # Cedar renderer happens in render_schema_json.
        member_of_namespaces = {ns for _, ns in action_ir.member_of}
        self.assertIn(None, member_of_namespaces)
        self.assertIn("Inventory", member_of_namespaces)

    def test_machine_type_parent_is_qualified(self):
        ns = self.engine.get_namespace("Inventory")
        mbu = ResourceType("MetaBusinessUnit", ns)
        machine = ResourceType("Machine", ns, parents=(mbu,))
        applies_to = AppliesTo(principals=(USER,), resources=(machine,))
        self.engine.register_action(
            "createMachineTag", ns, [ActionGroupBasename.ADMIN],
            applies_to=applies_to,
        )
        ir = build_schema_ir(self.engine)
        machine_ir = ir.namespaces["Inventory"].entity_types["Machine"]
        self.assertEqual(machine_ir.parents, ("Inventory::MetaBusinessUnit",))

    def test_action_help_text(self):
        ns = self.engine.get_namespace("Inventory")
        self.engine.register_action(
            "createMachineTag", ns, [ActionGroupBasename.ADMIN],
            applies_to=LEGACY_PERM_APPLIES_TO,
            help_text="Add a tag to a machine.",
        )
        ir = build_schema_ir(self.engine)
        self.assertEqual(
            ir.namespaces["Inventory"].actions["createMachineTag"].help_text,
            "Add a tag to a machine.",
        )

    def test_action_group_has_no_help_text(self):
        ns = self.engine.get_namespace("Inventory")
        self.engine.register_action(
            "createMachineTag", ns, [ActionGroupBasename.ADMIN],
            applies_to=LEGACY_PERM_APPLIES_TO,
            help_text="Add a tag to a machine.",
        )
        ir = build_schema_ir(self.engine)
        self.assertEqual(ir.namespaces["Inventory"].actions["AdminActions"].help_text, "")


class EntityTypeAncestorsTestCase(SimpleTestCase):
    def setUp(self):
        self.engine = Engine()

    def test_root_type_has_no_ancestor(self):
        ir = build_schema_ir(self.engine)
        self.assertEqual(ir.namespaces[None].entity_types["Role"].ancestors, ())

    def test_direct_parent(self):
        ir = build_schema_ir(self.engine)
        self.assertEqual(ir.namespaces[None].entity_types["User"].ancestors, ("Role",))

    def test_closure_is_transitive(self):
        ns = self.engine.get_namespace("Inventory")
        realm = ResourceType("Realm", ns)
        mbu = ResourceType("MetaBusinessUnit", ns, parents=(realm,))
        machine = ResourceType("Machine", ns, parents=(mbu,))
        self.engine.register_action(
            "yolo", ns, [ActionGroupBasename.ADMIN],
            applies_to=AppliesTo(principals=(USER,), resources=(machine,)),
        )
        ir = build_schema_ir(self.engine)
        self.assertEqual(
            ir.namespaces["Inventory"].entity_types["Machine"].ancestors,
            ("Inventory::MetaBusinessUnit", "Inventory::Realm"),
        )

    def test_closure_is_deduplicated(self):
        # A diamond: both parents of Machine lead back to Realm.
        ns = self.engine.get_namespace("Inventory")
        realm = ResourceType("Realm", ns)
        mbu = ResourceType("MetaBusinessUnit", ns, parents=(realm,))
        group = ResourceType("MachineGroup", ns, parents=(realm,))
        machine = ResourceType("Machine", ns, parents=(mbu, group))
        self.engine.register_action(
            "yolo", ns, [ActionGroupBasename.ADMIN],
            applies_to=AppliesTo(principals=(USER,), resources=(machine,)),
        )
        ir = build_schema_ir(self.engine)
        self.assertEqual(
            ir.namespaces["Inventory"].entity_types["Machine"].ancestors,
            ("Inventory::MetaBusinessUnit", "Inventory::MachineGroup", "Inventory::Realm"),
        )


class SchemaIRGetEntityTypeTestCase(SimpleTestCase):
    def setUp(self):
        self.engine = Engine()
        ns = self.engine.get_namespace("Inventory")
        mbu = ResourceType("MetaBusinessUnit", ns)
        self.engine.register_action(
            "yolo", ns, [ActionGroupBasename.ADMIN],
            applies_to=AppliesTo(principals=(USER,), resources=(ResourceType("Machine", ns, parents=(mbu,)),)),
        )
        self.ir = build_schema_ir(self.engine)

    def test_global_entity_type(self):
        self.assertEqual(self.ir.get_entity_type("Role").name, "Role")

    def test_namespaced_entity_type(self):
        entity_type = self.ir.get_entity_type("Inventory::Machine")
        self.assertEqual(entity_type.name, "Machine")
        self.assertEqual(entity_type.ancestors, ("Inventory::MetaBusinessUnit",))

    def test_unknown_name(self):
        self.assertIsNone(self.ir.get_entity_type("Inventory::Yolo"))

    def test_unknown_namespace(self):
        self.assertIsNone(self.ir.get_entity_type("Yolo::Machine"))


# ---------------------------------------------------------------------------
# JSON renderer
# ---------------------------------------------------------------------------


class RenderSchemaJSONTestCase(SimpleTestCase):
    def setUp(self):
        self.engine = Engine()

    def _build_inventory_engine(self):
        ns = self.engine.get_namespace("Inventory")
        machine = ResourceType("Machine", ns)
        self.engine.register_action(
            "createMachineTag", ns,
            [ActionGroupBasename.ADMIN],
            applies_to=AppliesTo(
                principals=(USER,),
                resources=(machine,),
                context={"tagName": AttrSpec(str, required=False)},
            ),
            legacy_perm="inventory.add_machinetag",
        )

    def test_every_namespace_has_both_keys(self):
        # cedarpy rejects schemas where a namespace block lacks either
        # entityTypes or actions.
        self._build_inventory_engine()
        schema = render_schema_json(build_schema_ir(self.engine))
        for ns_key, ns in schema.items():
            self.assertIn("entityTypes", ns, f"namespace {ns_key!r} missing entityTypes")
            self.assertIn("actions", ns, f"namespace {ns_key!r} missing actions")

    def test_global_namespace_key_is_empty_string(self):
        self._build_inventory_engine()
        schema = render_schema_json(build_schema_ir(self.engine))
        self.assertIn("", schema)
        self.assertIn("User", schema[""]["entityTypes"])

    def test_user_entity_type_uses_json_boolean_spelling(self):
        # Cedar's JSON schema uses "Boolean" (not "Bool", which is the
        # human-readable spelling).
        schema = render_schema_json(build_schema_ir(self.engine))
        user = schema[""]["entityTypes"]["User"]
        self.assertEqual(
            user["shape"]["attributes"]["is_superuser"]["type"],
            "Boolean",
        )

    def test_per_namespace_and_global_action_groups_both_appear(self):
        # Per-namespace and global action groups have distinct ids
        # ("AdminActions" vs "GlobalAdminActions"), so both safely live in
        # the schema. Cedar won't shadow.
        self._build_inventory_engine()
        schema = render_schema_json(build_schema_ir(self.engine))
        self.assertIn("AdminActions", schema["Inventory"]["actions"])
        self.assertIn("GlobalAdminActions", schema[""]["actions"])

    def test_member_of_references_both_groups(self):
        self._build_inventory_engine()
        schema = render_schema_json(build_schema_ir(self.engine))
        action = schema["Inventory"]["actions"]["createMachineTag"]
        # Inside the Inventory namespace block, the bare "AdminActions"
        # resolves to Inventory::Action::"AdminActions"; the bare
        # "GlobalAdminActions" to the global Action::"GlobalAdminActions".
        self.assertEqual(
            action["memberOf"],
            [{"id": "AdminActions"}, {"id": "GlobalAdminActions"}],
        )

    def test_applies_to_emits_principal_types_plural(self):
        # Cedar JSON uses principalTypes / resourceTypes (plural).
        self._build_inventory_engine()
        schema = render_schema_json(build_schema_ir(self.engine))
        applies_to = schema["Inventory"]["actions"]["createMachineTag"]["appliesTo"]
        self.assertIn("principalTypes", applies_to)
        self.assertIn("resourceTypes", applies_to)
        self.assertNotIn("principal", applies_to)  # that's the human-readable form
        self.assertNotIn("resource", applies_to)

    def test_optional_context_attribute_marked(self):
        self._build_inventory_engine()
        schema = render_schema_json(build_schema_ir(self.engine))
        ctx = schema["Inventory"]["actions"]["createMachineTag"]["appliesTo"]["context"]
        self.assertEqual(ctx["attributes"]["tagName"]["type"], "String")
        self.assertEqual(ctx["attributes"]["tagName"]["required"], False)


# ---------------------------------------------------------------------------
# cedarpy round-trip
# ---------------------------------------------------------------------------


class CedarpyRoundTripTestCase(SimpleTestCase):
    """Feed the rendered schema back to cedarpy.validate_policies to confirm
    it's both accepted and rejects typos with useful errors."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Use the real engine singleton — every Zentral contrib app has
        # registered its actions by the time tests run, so this is the
        # production-shape schema.
        cls.schema = render_schema_json(build_schema_ir(engine))

    def test_schema_validates_known_good_policy(self):
        # Identical to the seed policy used by tests.server_accounts.utils.
        r = validate_policies(
            'permit (principal in Role::"0", action, resource);',
            self.schema,
        )
        self.assertTrue(r.validation_passed, msg=[str(e) for e in r.errors])

    def test_schema_validates_global_action_group_reference(self):
        r = validate_policies(
            'permit (principal, action in Action::"GlobalAdminActions", resource);',
            self.schema,
        )
        self.assertTrue(r.validation_passed, msg=[str(e) for e in r.errors])

    def test_schema_validates_per_namespace_action_group_reference(self):
        r = validate_policies(
            'permit (principal, action in Inventory::Action::"AdminActions", resource);',
            self.schema,
        )
        self.assertTrue(r.validation_passed, msg=[str(e) for e in r.errors])

    def test_schema_rejects_action_id_typo(self):
        r = validate_policies(
            'permit (principal, action == Inventory::Action::"createMachineTagzz", resource);',
            self.schema,
        )
        self.assertFalse(r.validation_passed)
        errors = [str(e) for e in r.errors]
        self.assertTrue(
            any('unrecognized action' in e for e in errors),
            msg=f"expected 'unrecognized action' in errors, got: {errors!r}",
        )

    def test_schema_rejects_unknown_principal_type(self):
        r = validate_policies(
            'permit (principal == Bogus::"x", action, resource);',
            self.schema,
        )
        self.assertFalse(r.validation_passed)

    def test_documentation_fields_are_not_rendered(self):
        # Cedar rejects an attribute record that carries a key it does not
        # know, so help_text and values must never reach the JSON schema. The
        # production schema has both, on Santa::Action::"forceCleanSync".
        blob = json.dumps(self.schema)
        self.assertNotIn("help_text", blob)
        self.assertNotIn("helpText", blob)
        self.assertNotIn("CLEAN_ALL", blob)

    def test_schema_validates_a_context_condition_on_a_documented_value(self):
        r = validate_policies(
            'permit (principal, action == Santa::Action::"forceCleanSync", resource)'
            ' when { context.syncType == "CLEAN_ALL" };',
            self.schema,
        )
        self.assertTrue(r.validation_passed, msg=[str(e) for e in r.errors])


# ---------------------------------------------------------------------------
# Human-readable renderer (smoke)
# ---------------------------------------------------------------------------


class RenderSchemaHumanTestCase(SimpleTestCase):
    def setUp(self):
        self.engine = Engine()

    def test_global_entity_types_rendered_at_top(self):
        out = render_schema_human(build_schema_ir(self.engine))
        # Built-ins appear unqualified at the top.
        self.assertIn("entity Role;", out)
        self.assertIn("entity User in [Role] = {", out)
        self.assertIn("is_superuser: Bool", out)
        self.assertIn("entity ServiceAccount in [Role];", out)
        self.assertIn("entity System;", out)

    def test_namespaced_actions_wrapped_in_namespace_block(self):
        ns = self.engine.get_namespace("Inventory")
        self.engine.register_action(
            "syncStuff", ns, [ActionGroupBasename.ADMIN],
            applies_to=LEGACY_PERM_APPLIES_TO,
        )
        out = render_schema_human(build_schema_ir(self.engine))
        self.assertIn("namespace Inventory {", out)
        self.assertIn('action "syncStuff"', out)
        # Action belongs to both the per-namespace and the global group.
        # The per-namespace one is referenced bare ("AdminActions"); the
        # global one needs the explicit Action::"…" form.
        self.assertIn('in ["AdminActions", Action::"GlobalAdminActions"]', out)

    def test_documentation_fields_are_not_rendered(self):
        ns = self.engine.get_namespace("Santa")
        self.engine.register_action(
            "forceCleanSync", ns, [ActionGroupBasename.ADMIN],
            applies_to=AppliesTo(
                principals=(USER,),
                resources=(SYSTEM,),
                context={"syncType": AttrSpec(str, help_text="Yolo.", values=["CLEAN"])},
            ),
            help_text="Queue a clean sync.",
        )
        out = render_schema_human(build_schema_ir(self.engine))
        self.assertIn("syncType: String", out)
        self.assertNotIn("Yolo.", out)
        self.assertNotIn("CLEAN", out)
        self.assertNotIn("Queue a clean sync.", out)

    def test_human_uses_bool_not_boolean(self):
        out = render_schema_human(build_schema_ir(self.engine))
        # Human-readable Cedar spells the boolean primitive "Bool".
        self.assertIn("Bool", out)
        self.assertNotIn(": Boolean", out)


# ---------------------------------------------------------------------------
# Management command smoke
# ---------------------------------------------------------------------------


class PBACDumpSchemaCommandTestCase(TestCase):
    def test_json_format_is_parseable(self):
        import io
        import json
        from django.core.management import call_command

        out = io.StringIO()
        call_command("pbac_dump_schema", "--format=json", stdout=out)
        data = json.loads(out.getvalue())
        self.assertIn("", data)
        self.assertIn("Inventory", data)

    def test_human_format_is_non_empty(self):
        import io
        from django.core.management import call_command

        out = io.StringIO()
        call_command("pbac_dump_schema", "--format=human", stdout=out)
        text = out.getvalue()
        self.assertIn("entity User", text)
        self.assertIn("namespace Inventory", text)

import uuid

from cedarpy import format_policies
from django.contrib.auth.models import Group
from django.db.models import Q
from django.test import SimpleTestCase, TestCase
from django.utils.crypto import get_random_string

from accounts.models import Policy, User
from pbac.cedar import policies_cache
from pbac.entities import Action, Namespace
from pbac.scoping import _MAX_DEPTH, SQLMap, compile_policies, scope_queryset, values_q, visible_rows
from pbac.types import USER, AppliesTo, AttrSpec, ResourceType, SetOf
from zentral.contrib.inventory.pbac import MACHINE_RESOURCE_TYPE
from zentral.contrib.turbo.models import OneTimeJobMachine
from zentral.contrib.turbo.pbac import (CONFIGURATION_RESOURCE_TYPE, JOB_RESOURCE_TYPE,
                                        ONE_TIME_JOB_MACHINE_RESOURCE_TYPE, ONE_TIME_JOB_RESOURCE_TYPE,
                                        ViewOneTimeJobMachineRequest, view_one_time_job_machine_action)
from tests.turbo.utils import force_configuration, force_mscp_check, force_one_time_job, force_script


# a map without the meta business units, and with functions for the machine and the configuration
SQL_MAP = SQLMap(
    OneTimeJobMachine, ONE_TIME_JOB_MACHINE_RESOURCE_TYPE,
    entities={
        ONE_TIME_JOB_MACHINE_RESOURCE_TYPE: "pk",
        MACHINE_RESOURCE_TYPE: lambda entity_ids: values_q("serial_number", entity_ids),
        ONE_TIME_JOB_RESOURCE_TYPE: "one_time_job",
        CONFIGURATION_RESOURCE_TYPE: lambda entity_ids: values_q("one_time_job__configuration__name", entity_ids),
    },
    attributes={"job": "one_time_job__job", "job.kind": "one_time_job__job__kind"},
)
JOB_UUID = "0f6c2c1a-3c1e-4bb0-9a43-9e5b4d0e8f21"


class ViewRowWithContextRequest(ViewOneTimeJobMachineRequest):
    pbac_action = Action("viewRowWithContext", Namespace("Tests"),
                         applies_to=AppliesTo(principals=(USER,), resources=(ONE_TIME_JOB_MACHINE_RESOURCE_TYPE,),
                                              context={"kind": AttrSpec(str)}))

    def __init__(self, user_obj, job_machine, machine):
        super().__init__(user_obj, job_machine, machine)
        self.context = {"kind": job_machine.one_time_job.job.kind}


# the JSON policy format of Cedar

RESOURCE = {"unknown": [{"Value": "resource"}]}


def value(v):
    return {"Value": v}


def entity(entity_type, entity_id):
    return value({"__entity": {"type": entity_type, "id": entity_id}})


def attr(*names):
    expr = RESOURCE
    for name in names:
        expr = {".": {"left": expr, "attr": name}}
    return expr


def binary(op, left, right):
    return {op: {"left": left, "right": right}}


def resource_in(entity_type, entity_id):
    return binary("in", RESOURCE, entity(entity_type, entity_id))


def policy(effect, *conditions, **scopes):
    p = {"effect": effect, "conditions": [{"kind": kind, "body": body} for kind, body in conditions]}
    for scope in ("principal", "action", "resource"):
        p[scope] = scopes.get(scope, {"op": "All"})
    return p


def permit(body, kind="when"):
    return policy("permit", (kind, body))


def forbid(body, kind="when"):
    return policy("forbid", (kind, body))


ROW = entity("Turbo::OneTimeJobMachine", "5")
IN_ROW = binary("in", RESOURCE, ROW)
KIND_IS_SCRIPT = binary("==", attr("job", "kind"), value("script"))


class ValuesQTestCase(SimpleTestCase):
    def test_one_value(self):
        self.assertEqual(values_q("pk", [5]), Q(pk=5))

    def test_values(self):
        self.assertEqual(values_q("pk", [6, 5, 6]), Q(pk__in=[6, 5]))

    def test_no_value(self):
        self.assertIs(values_q("pk", []), False)

    def test_a_nul(self):
        # no text column has one, and psycopg2 refuses one in a parameter
        self.assertIs(values_q("serial_number", ["C02\x00"]), False)
        self.assertEqual(values_q("serial_number", ["C02\x00", "C02"]), Q(serial_number="C02"))


class SQLMapTestCase(TestCase):
    def test_an_entity_type_that_is_not_an_ancestor(self):
        with self.assertRaises(ValueError) as cm:
            SQLMap(OneTimeJobMachine, ONE_TIME_JOB_MACHINE_RESOURCE_TYPE,
                   {JOB_RESOURCE_TYPE: "one_time_job__job"}, {})
        self.assertEqual(cm.exception.args[0], "Turbo::Job is not an ancestor type of Turbo::OneTimeJobMachine")

    def test_an_entity_lookup_that_is_not_a_primary_key(self):
        # the id of a machine is its URL-safe serial number, not the column
        with self.assertRaises(ValueError) as cm:
            SQLMap(OneTimeJobMachine, ONE_TIME_JOB_MACHINE_RESOURCE_TYPE,
                   {MACHINE_RESOURCE_TYPE: "serial_number"}, {})
        self.assertEqual(cm.exception.args[0], "serial_number is not the primary key of an entity")

    def test_an_entity_attribute_that_is_not_a_primary_key(self):
        with self.assertRaises(ValueError) as cm:
            SQLMap(OneTimeJobMachine, ONE_TIME_JOB_MACHINE_RESOURCE_TYPE, {}, {"job": "one_time_job__job__kind"})
        self.assertEqual(cm.exception.args[0], "one_time_job__job__kind is not the primary key of an entity")

    def test_an_unknown_attribute(self):
        with self.assertRaises(ValueError) as cm:
            SQLMap(OneTimeJobMachine, ONE_TIME_JOB_MACHINE_RESOURCE_TYPE, {},
                   {"job.name": "one_time_job__job__name"})
        self.assertEqual(cm.exception.args[0],
                         "job.name is not a path of required attributes of Turbo::OneTimeJobMachine")

    def test_an_attribute_of_a_primitive(self):
        with self.assertRaises(ValueError):
            SQLMap(OneTimeJobMachine, ONE_TIME_JOB_MACHINE_RESOURCE_TYPE, {}, {"job.kind.x": "one_time_job__job"})

    def test_an_optional_attribute(self):
        # Cedar errors on it when it is not there, and skips the policy
        resource_type = ResourceType("Row", Namespace("Tests"), attrs={"name": AttrSpec(str, required=False)})
        with self.assertRaises(ValueError):
            SQLMap(OneTimeJobMachine, resource_type, {}, {"name": "serial_number"})

    def test_an_attribute_that_is_a_set(self):
        resource_type = ResourceType("Row", Namespace("Tests"), attrs={"names": AttrSpec(SetOf(str))})
        with self.assertRaises(ValueError) as cm:
            SQLMap(OneTimeJobMachine, resource_type, {}, {"names": "serial_number"})
        self.assertEqual(cm.exception.args[0], "names is not an entity or a primitive")


class CompilePoliciesTestCase(TestCase):
    maxDiff = None

    def compile(self, *policies):
        return compile_policies({f"policy{i}": p for i, p in enumerate(policies)}, SQL_MAP)

    def assertUnsupported(self, body):
        self.assertIsNone(self.compile(permit(body)))

    # constants

    def test_no_policies(self):
        self.assertIs(self.compile(), False)

    def test_a_true_permit(self):
        self.assertIs(self.compile(permit(value(True))), True)

    def test_a_false_permit(self):
        self.assertIs(self.compile(permit(value(False))), False)

    def test_a_forbid_without_a_permit(self):
        self.assertIs(self.compile(forbid(IN_ROW)), False)

    def test_a_true_forbid(self):
        self.assertIs(self.compile(permit(IN_ROW), forbid(value(True))), False)

    def test_a_false_forbid(self):
        self.assertEqual(self.compile(permit(IN_ROW), forbid(value(False))), Q(pk=5))

    def test_annotations(self):
        p = permit(value(True))
        p["annotations"] = {"id": "yolo"}
        self.assertIs(self.compile(p), True)

    # in

    def test_in_the_row(self):
        self.assertEqual(self.compile(permit(IN_ROW)), Q(pk=5))

    def test_in_the_row_with_another_spelling_of_the_id(self):
        # Cedar compares the ids as strings
        self.assertIs(self.compile(permit(resource_in("Turbo::OneTimeJobMachine", "05"))), False)

    def test_in_the_row_with_an_id_that_is_not_a_number(self):
        self.assertIs(self.compile(permit(resource_in("Turbo::OneTimeJobMachine", "yolo"))), False)

    def test_in_a_parent(self):
        self.assertEqual(self.compile(permit(resource_in("Turbo::OneTimeJob", JOB_UUID))),
                         Q(one_time_job=uuid.UUID(JOB_UUID)))

    def test_in_a_parent_with_an_upper_case_uuid(self):
        self.assertIs(self.compile(permit(resource_in("Turbo::OneTimeJob", JOB_UUID.upper()))), False)

    def test_in_a_parent_with_an_id_that_is_not_a_uuid(self):
        self.assertIs(self.compile(permit(resource_in("Turbo::OneTimeJob", "yolo"))), False)

    def test_in_a_text_id(self):
        self.assertEqual(self.compile(permit(resource_in("Inventory::Machine", "0123456789"))),
                         Q(serial_number="0123456789"))

    def test_in_an_ancestor_with_a_function(self):
        self.assertEqual(self.compile(permit(resource_in("Turbo::Configuration", "yolo"))),
                         Q(one_time_job__configuration__name="yolo"))

    def test_in_an_ancestor_that_the_map_does_not_have(self):
        self.assertUnsupported(resource_in("Inventory::MetaBusinessUnit", "1"))

    def test_in_a_type_that_is_not_an_ancestor(self):
        # the job is an attribute, not a parent
        for entity_type in ("Turbo::Job", "Turbo::RecurringJob", "Yolo"):
            self.assertIs(self.compile(permit(resource_in(entity_type, "1"))), False)

    def test_in_a_set(self):
        expr = binary("in", RESOURCE, {"Set": [entity("Turbo::OneTimeJob", JOB_UUID), ROW,
                                               entity("Turbo::Job", JOB_UUID)]})
        self.assertEqual(self.compile(permit(expr)), Q(one_time_job=uuid.UUID(JOB_UUID)) | Q(pk=5))

    def test_in_a_set_of_one_type(self):
        # one Q for each type, not one for each element. The ids that no row has are not in it.
        expr = binary("in", RESOURCE, {"Set": [ROW, entity("Turbo::OneTimeJobMachine", "6"),
                                               entity("Turbo::OneTimeJobMachine", "05"), ROW]})
        self.assertEqual(self.compile(permit(expr)), Q(pk__in=[5, 6]))

    def test_in_a_set_of_one_type_with_one_id_that_a_row_can_have(self):
        expr = binary("in", RESOURCE, {"Set": [entity("Turbo::OneTimeJobMachine", "yolo"), ROW]})
        self.assertEqual(self.compile(permit(expr)), Q(pk=5))

    def test_in_a_set_of_ids_that_no_row_has(self):
        expr = binary("in", RESOURCE, {"Set": [entity("Turbo::OneTimeJobMachine", "yolo"),
                                               entity("Turbo::OneTimeJob", JOB_UUID.upper())]})
        self.assertIs(self.compile(permit(expr)), False)

    def test_in_a_set_with_a_function(self):
        expr = binary("in", RESOURCE, {"Set": [entity("Inventory::Machine", "C02A"), ROW,
                                               entity("Inventory::Machine", "C02B")]})
        self.assertEqual(self.compile(permit(expr)), Q(serial_number__in=["C02A", "C02B"]) | Q(pk=5))

    def test_in_a_set_with_an_ancestor_that_the_map_does_not_have(self):
        self.assertUnsupported(binary("in", RESOURCE, {"Set": [ROW, entity("Inventory::MetaBusinessUnit", "1")]}))

    def test_in_an_empty_set(self):
        self.assertIs(self.compile(permit(binary("in", RESOURCE, {"Set": []}))), False)

    def test_in_a_set_with_a_value_that_is_not_an_entity(self):
        # Cedar errors on it, and skips the policy
        self.assertUnsupported(binary("in", RESOURCE, {"Set": [ROW, value("yolo")]}))

    def test_in_a_set_that_is_not_a_list(self):
        self.assertUnsupported(binary("in", RESOURCE, {"Set": ROW}))

    def test_in_a_string(self):
        self.assertUnsupported(binary("in", RESOURCE, value("yolo")))

    def test_an_attribute_in(self):
        self.assertUnsupported(binary("in", attr("job"), entity("Turbo::Configuration", "1")))

    def test_in_the_resource(self):
        self.assertUnsupported(binary("in", RESOURCE, RESOURCE))

    # is

    def test_is_the_row_type(self):
        self.assertIs(self.compile(permit({"is": {"left": RESOURCE, "entity_type": "Turbo::OneTimeJobMachine"}})),
                      True)

    def test_is_another_type(self):
        for entity_type in ("Turbo::OneTimeJob", "Inventory::Machine", "Yolo"):
            self.assertIs(self.compile(permit({"is": {"left": RESOURCE, "entity_type": entity_type}})), False)

    def test_is_in(self):
        # Cedar gives `is … in …` as an is and an in. An in in the is must not be lost.
        self.assertUnsupported({"is": {"left": RESOURCE, "entity_type": "Turbo::OneTimeJobMachine",
                                       "in": entity("Turbo::OneTimeJob", JOB_UUID)}})

    def test_is_not_on_the_resource(self):
        self.assertUnsupported({"is": {"left": attr("job"), "entity_type": "Turbo::Job"}})

    def test_is_a_type_that_is_not_a_string(self):
        self.assertUnsupported({"is": {"left": RESOURCE, "entity_type": ["Turbo", "OneTimeJobMachine"]}})

    # ==

    def test_the_resource_equal_to_a_row(self):
        expr = binary("==", RESOURCE, entity("Turbo::OneTimeJobMachine", "5"))
        self.assertEqual(self.compile(permit(expr)), Q(pk=5))

    def test_a_row_equal_to_the_resource(self):
        expr = binary("==", entity("Turbo::OneTimeJobMachine", "5"), RESOURCE)
        self.assertEqual(self.compile(permit(expr)), Q(pk=5))

    def test_the_resource_equal_to_an_ancestor(self):
        expr = binary("==", RESOURCE, entity("Turbo::OneTimeJob", JOB_UUID))
        self.assertIs(self.compile(permit(expr)), False)

    def test_the_resource_equal_to_a_string(self):
        self.assertIs(self.compile(permit(binary("==", RESOURCE, value("5")))), False)

    def test_a_string_attribute(self):
        self.assertEqual(self.compile(permit(KIND_IS_SCRIPT)), Q(one_time_job__job__kind="script"))

    def test_a_string_attribute_on_the_right(self):
        expr = binary("==", value("script"), attr("job", "kind"))
        self.assertEqual(self.compile(permit(expr)), Q(one_time_job__job__kind="script"))

    def test_a_string_attribute_and_other_types(self):
        # Cedar: two values of different types are not equal, and it is not an error
        for literal in (value(3), value(True), entity("Turbo::Job", "3")):
            self.assertIs(self.compile(permit(binary("==", attr("job", "kind"), literal))), False)

    def test_an_entity_attribute(self):
        expr = binary("==", attr("job"), entity("Turbo::Job", JOB_UUID))
        self.assertEqual(self.compile(permit(expr)), Q(one_time_job__job=uuid.UUID(JOB_UUID)))

    def test_an_entity_attribute_and_other_values(self):
        for literal in (entity("Turbo::Job", JOB_UUID.upper()), entity("Turbo::Job", "3"),
                        entity("Turbo::Script", JOB_UUID), value(JOB_UUID), value(3)):
            self.assertIs(self.compile(permit(binary("==", attr("job"), literal))), False)

    def test_not_equal(self):
        self.assertEqual(self.compile(permit(binary("!=", attr("job", "kind"), value("script")))),
                         ~Q(one_time_job__job__kind="script"))

    def test_an_unknown_attribute(self):
        self.assertUnsupported(binary("==", attr("yolo"), value("script")))

    def test_an_attribute_of_a_string(self):
        self.assertUnsupported(binary("==", attr("job", "kind", "yolo"), value("script")))

    def test_two_attributes(self):
        self.assertUnsupported(binary("==", attr("job", "kind"), attr("job", "kind")))

    def test_two_literals(self):
        self.assertUnsupported(binary("==", value("a"), value("a")))

    def test_an_extension_value(self):
        self.assertUnsupported(binary("==", attr("job", "kind"),
                                      value({"__extn": {"fn": "ip", "arg": "127.0.0.1"}})))

    def test_an_entity_without_an_id(self):
        self.assertUnsupported(binary("in", RESOURCE, value({"__entity": {"type": "Turbo::OneTimeJob"}})))

    def test_a_nul(self):
        # no text column has one, and psycopg2 refuses one in a parameter
        for expr, result in ((binary("==", attr("job", "kind"), value("scr\x00ipt")), False),
                             (binary("!=", attr("job", "kind"), value("scr\x00ipt")), True),
                             (resource_in("Inventory::Machine", "C02\x00"), False)):
            self.assertIs(self.compile(permit(expr)), result)

    # boolean operators

    def test_and(self):
        self.assertEqual(self.compile(permit(binary("&&", IN_ROW, KIND_IS_SCRIPT))),
                         Q(pk=5) & Q(one_time_job__job__kind="script"))

    def test_or(self):
        self.assertEqual(self.compile(permit(binary("||", IN_ROW, KIND_IS_SCRIPT))),
                         Q(pk=5) | Q(one_time_job__job__kind="script"))

    def test_not(self):
        self.assertEqual(self.compile(permit({"!": {"arg": IN_ROW}})), ~Q(pk=5))

    def test_not_a_constant(self):
        self.assertIs(self.compile(permit({"!": {"arg": value(False)}})), True)

    def test_constants_in_and_and_or(self):
        for op, left, right, result in (("&&", value(True), IN_ROW, Q(pk=5)),
                                        ("&&", IN_ROW, value(True), Q(pk=5)),
                                        ("&&", value(False), IN_ROW, False),
                                        ("&&", IN_ROW, value(False), False),
                                        ("||", value(False), IN_ROW, Q(pk=5)),
                                        ("||", IN_ROW, value(False), Q(pk=5)),
                                        ("||", value(True), IN_ROW, True),
                                        ("||", IN_ROW, value(True), True)):
            self.assertEqual(self.compile(permit(binary(op, left, right))), result)

    def test_an_operand_that_decides_a_chain(self):
        # Cedar stops at it, so the operands after it can be outside the subset, but not the operands before it
        unsupported = {"has": {"left": RESOURCE, "attr": "job"}}
        is_another_type = {"is": {"left": RESOURCE, "entity_type": "Turbo::JobUpload"}}
        is_the_row_type = {"is": {"left": RESOURCE, "entity_type": "Turbo::OneTimeJobMachine"}}
        not_an_ancestor = resource_in("Turbo::Job", JOB_UUID)
        for op, decided, result in (("&&", value(False), False),
                                    ("&&", is_another_type, False),
                                    ("&&", not_an_ancestor, False),
                                    ("||", value(True), True),
                                    ("||", is_the_row_type, True)):
            self.assertIs(self.compile(permit(binary(op, decided, unsupported))), result)
            self.assertIs(self.compile(permit(binary(op, binary(op, IN_ROW, decided), unsupported))), result)
            self.assertIsNone(self.compile(permit(binary(op, unsupported, decided))))
        # the shape of a residual: the scopes first, then the condition
        residual = binary("&&", value(True), binary("&&", value(True), binary("&&", is_another_type, unsupported)))
        self.assertEqual(self.compile(permit(IN_ROW), forbid(residual)), Q(pk=5))
        self.assertIs(self.compile(permit({"!": {"arg": binary("&&", is_another_type, unsupported)}})), True)

    def test_unless(self):
        self.assertEqual(self.compile(permit(IN_ROW, kind="unless")), ~Q(pk=5))

    def test_two_conditions(self):
        p = policy("permit", ("when", IN_ROW), ("unless", KIND_IS_SCRIPT))
        self.assertEqual(self.compile(p), Q(pk=5) & ~Q(one_time_job__job__kind="script"))

    def test_a_long_chain(self):
        # Cedar nests a || b || c … as deep as the chain is long, deeper than the recursion limit of Python
        for op, connector in (("||", Q.OR), ("&&", Q.AND)):
            expr = resource_in("Turbo::OneTimeJobMachine", "0")
            for i in range(1, 3000):
                expr = binary(op, expr, resource_in("Turbo::OneTimeJobMachine", str(i)))
            self.assertEqual(self.compile(permit(expr)), Q(*(("pk", i) for i in range(3000)), _connector=connector))

    def test_nesting_at_the_limit(self):
        expr = IN_ROW
        for _ in range(_MAX_DEPTH):
            expr = {"!": {"arg": expr}}
        self.assertEqual(self.compile(permit(expr)), Q(pk=5) if _MAX_DEPTH % 2 == 0 else ~Q(pk=5))

    def test_nesting_deeper_than_the_limit(self):
        expr = IN_ROW
        for _ in range(_MAX_DEPTH + 1):
            expr = {"!": {"arg": expr}}
        self.assertUnsupported(expr)

    def test_permits_and_forbids(self):
        in_job = resource_in("Turbo::OneTimeJob", JOB_UUID)
        self.assertEqual(self.compile(permit(IN_ROW), permit(KIND_IS_SCRIPT), forbid(in_job), forbid(IN_ROW)),
                         (Q(pk=5) | Q(one_time_job__job__kind="script"))
                         & ~(Q(one_time_job=uuid.UUID(JOB_UUID)) | Q(pk=5)))

    # what this module does not write as SQL

    def test_unsupported_expressions(self):
        for body in (
            {"has": {"left": RESOURCE, "attr": "job"}},
            {"like": {"left": attr("job", "kind"), "pattern": [{"Literal": "s"}, "Wildcard"]}},
            {"if-then-else": {"if": IN_ROW, "then": value(True), "else": value(False)}},
            binary("==", binary("+", value(1), value(1)), value(2)),
            binary("==", {".": {"left": {"unknown": [{"Value": "context"}]}, "attr": "a"}}, value(1)),
            value("yolo"),
            {"&&": {"left": IN_ROW}},
            {"!": IN_ROW},
            {"in": IN_ROW, "!": IN_ROW},
            "yolo",
        ):
            self.assertUnsupported(body)

    def test_a_scope(self):
        for scope in ("principal", "action", "resource"):
            p = permit(value(True))
            p[scope] = {"op": "==", "entity": {"type": "User", "id": "1"}}
            self.assertIsNone(self.compile(p))

    def test_a_scope_that_is_not_there(self):
        p = permit(value(True))
        del p["resource"]
        self.assertIsNone(self.compile(p))

    def test_an_unknown_key(self):
        p = permit(value(True))
        p["yolo"] = 1
        self.assertIsNone(self.compile(p))

    def test_no_conditions(self):
        p = permit(value(True))
        del p["conditions"]
        self.assertIsNone(self.compile(p))

    def test_an_unknown_effect(self):
        self.assertIsNone(self.compile(policy("yolo", ("when", value(True)))))

    def test_an_unknown_condition_kind(self):
        self.assertIsNone(self.compile(policy("permit", ("yolo", value(True)))))

    def test_a_policy_that_is_not_a_dict(self):
        self.assertIsNone(self.compile("yolo"))

    # a change of the format gives None, not an error

    def test_policies_that_are_not_a_dict(self):
        self.assertIsNone(compile_policies([permit(value(True))], SQL_MAP))

    def test_conditions_that_are_not_a_list(self):
        p = permit(value(True))
        p["conditions"] = None
        self.assertIsNone(self.compile(p))

    def test_an_entity_type_that_is_not_a_string(self):
        literal = value({"__entity": {"type": ["Turbo", "OneTimeJob"], "id": JOB_UUID}})
        self.assertUnsupported(binary("in", RESOURCE, literal))

    def test_an_entity_id_that_is_not_a_string(self):
        self.assertUnsupported(resource_in("Turbo::OneTimeJobMachine", 5))

    def test_an_attribute_name_that_is_not_a_string(self):
        self.assertUnsupported(binary("==", {".": {"left": RESOURCE, "attr": ["job"]}}, value("script")))

    def test_one_unsupported_policy_is_enough(self):
        self.assertIsNone(self.compile(permit(IN_ROW), forbid({"has": {"left": RESOURCE, "attr": "job"}})))


class ScopeQuerysetTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(get_random_string(12), f"{get_random_string(12)}@zentral.com")
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.add(cls.group)
        configuration = force_configuration()
        cls.rows = [
            OneTimeJobMachine.objects.create(one_time_job=force_one_time_job(configuration=configuration, job=job),
                                             serial_number=get_random_string(12))
            for job in (force_script().job, force_mscp_check().job)
        ]

    def setUp(self):
        policies_cache.clear()
        self.queryset = OneTimeJobMachine.objects.all()

    def _policy(self, condition="", forbid=""):
        Policy.objects.filter(name="Tests").delete()
        Policy.objects.create(name="Tests", source=format_policies(
            f'permit (principal in Role::"{self.group.pk}", '
            f'action == Turbo::Action::"viewOneTimeJobMachine", resource) {condition};\n{forbid}'
        ))
        policies_cache.clear()

    def _scope(self, user=None, action=view_one_time_job_machine_action):
        return scope_queryset(user or self.user, action, self.queryset, SQL_MAP)

    def test_a_superuser(self):
        superuser = User.objects.create_user(get_random_string(12), f"{get_random_string(12)}@zentral.com",
                                             is_superuser=True)
        self.assertIs(self._scope(superuser), self.queryset)

    def test_no_policy(self):
        queryset = self._scope()
        self.assertTrue(queryset.query.is_empty())
        self.assertEqual(list(queryset), [])

    def test_a_permit_for_all_the_rows(self):
        self._policy()
        self.assertIs(self._scope(), self.queryset)

    def test_an_action_with_a_context(self):
        # Cedar evaluates the list with an empty context, and a forbid that reads it does not apply
        action = Action("viewRow", Namespace("Tests"),
                        applies_to=AppliesTo(principals=(USER,), resources=(ONE_TIME_JOB_MACHINE_RESOURCE_TYPE,),
                                             context={"kind": AttrSpec(str)}))
        superuser = User.objects.create_user(get_random_string(12), f"{get_random_string(12)}@zentral.com",
                                             is_superuser=True)
        for user in (self.user, superuser):
            with self.assertRaises(ValueError) as cm:
                self._scope(user, action)
            self.assertEqual(cm.exception.args[0], "An action with a context needs one decision for each row")

    def test_a_request_that_cedar_cannot_read(self):
        self._policy()
        with self.assertLogs("zentral.pbac.cedar", level="ERROR"):
            queryset = self._scope(action=Action('view"OneTimeJobMachine', Namespace("Turbo")))
        self.assertTrue(queryset.query.is_empty())

    def test_a_policy_that_is_not_supported(self):
        self._policy('when { resource.job.kind like "scr*" }')
        self.assertIsNone(self._scope())

    def test_a_policy_of_another_type_that_is_not_supported(self):
        # resource.artifact is not in the map, but Cedar never reads it on a row of this list
        self._policy(forbid='forbid (principal, action, resource is Turbo::JobUpload) '
                            'when { resource.artifact == "archive" };')
        self.assertIs(self._scope(), self.queryset)

    def test_a_filter(self):
        self._policy('when { resource.job.kind == "script" }')
        self.assertEqual(list(self._scope()), [self.rows[0]])

    def test_policies_that_are_true_for_all_the_rows(self):
        # Cedar does not know that a job is not a parent of the row, the SQL map does
        job_pk = self.rows[0].one_time_job.job.pk
        self._policy(forbid=f'forbid (principal, action, resource) when {{ resource in Turbo::Job::"{job_pk}" }};')
        self.assertIs(self._scope(), self.queryset)

    def test_policies_that_are_false_for_all_the_rows(self):
        self._policy(f'when {{ resource in Turbo::Job::"{self.rows[0].one_time_job.job.pk}" }}')
        self.assertTrue(self._scope().query.is_empty())

    def test_a_long_chain(self):
        # longer than the recursion limit of Python, shorter than the one of Cedar
        kinds = " || ".join(f'resource.job.kind == "k{i}"' for i in range(1500))
        self._policy(f'when {{ {kinds} || resource.job.kind == "script" }}')
        self.assertEqual(list(self._scope()), [self.rows[0]])

    def test_the_deepest_nesting_is_valid_sql(self):
        # each level alternates the operator, so that the Q has the same depth
        expr = KIND_IS_SCRIPT
        for i in range(_MAX_DEPTH):
            if i % 2:
                expr = binary("&&", binary("!=", attr("job", "kind"), value("yolo")), expr)
            else:
                expr = binary("||", resource_in("Turbo::OneTimeJobMachine", "0"), expr)
        q = compile_policies({"policy0": permit(expr)}, SQL_MAP)
        self.assertEqual(list(self.queryset.filter(q)), [self.rows[0]])

    # visible_rows

    def test_visible_rows_with_an_action_with_a_context(self):
        # no list without a row: one decision for each row, with the context of the row
        Policy.objects.filter(name="Tests").delete()
        Policy.objects.create(name="Tests", source=format_policies(
            f'permit (principal in Role::"{self.group.pk}", action == {ViewRowWithContextRequest.pbac_action}, '
            'resource) unless { context.kind == "script" };'
        ))
        policies_cache.clear()
        self.assertEqual(list(visible_rows(self.user, ViewRowWithContextRequest, self.queryset)), [self.rows[1]])
        superuser = User.objects.create_user(get_random_string(12), f"{get_random_string(12)}@zentral.com",
                                             is_superuser=True)
        self.assertEqual(set(visible_rows(superuser, ViewRowWithContextRequest, self.queryset)), set(self.rows))

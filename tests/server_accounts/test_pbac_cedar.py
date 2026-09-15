from cedarpy import format_policies, PolicySet
from django.contrib.auth.models import Group
from django.core.exceptions import PermissionDenied
from django.test import RequestFactory, TestCase
from django.utils.crypto import get_random_string

from accounts.models import Policy, User
from pbac.cedar import (_serialize_requests, authorize_request, authorize_requests,
                        PoliciesCache, policies_cache)
from pbac.engine import engine
from pbac.entities import Action, Entity, Namespace, Principal, Request, Resource
from zentral.utils.drf import PBACPermission
from zentral.utils.views import PBACViewMixin
from .utils import force_policy


INVENTORY = Namespace("Inventory")


class SerializeMixin:
    def serialize(self, requests):
        serialized_requests, entities = _serialize_requests(requests)
        uids = [(e["uid"]["type"], e["uid"]["id"]) for e in entities]
        self.assertEqual(len(uids), len(set(uids)))
        # a parent that is missing from the array is an entity without attributes
        # and without parents of its own, and cedar reports no error for it
        for entity in entities:
            for parent in entity["parents"]:
                self.assertIn((parent["type"], parent["id"]), uids)
        return serialized_requests, dict(zip(uids, entities))


class PBACCedarTestCase(TestCase):
    def test_authorize_requests_no_requests(self):
        self.assertIsNone(authorize_requests([]))

    def test_policies_cache_with_sync(self):
        force_policy()
        pc = PoliciesCache(with_sync=True)
        self.assertFalse(pc._sync_started)
        self.assertIsNone(pc._last_refresh_ts)
        # not cached: policies are parsed once into a reusable PolicySet
        policy_set = pc.policy_set
        self.assertIsInstance(policy_set, PolicySet)
        self.assertEqual(len(policy_set), 1)
        self.assertTrue(pc._sync_started)
        ts = pc._last_refresh_ts
        self.assertIsNotNone(ts)
        # cached: the same parsed handle is returned, no refresh
        self.assertIs(pc.policy_set, policy_set)
        self.assertEqual(ts, pc._last_refresh_ts)
        # clear
        pc.clear()
        self.assertIsNone(pc._policy_set)


class PBACSchemaCachedPropertyTestCase(TestCase):
    """engine.cedar_schema_json is a cached property built on first access."""

    def setUp(self):
        # Bust the cache so each test sees a fresh build.
        try:
            del engine.cedar_schema_json
        except AttributeError:
            pass

    def test_cedar_schema_json_is_cached(self):
        first = engine.cedar_schema_json
        second = engine.cedar_schema_json
        self.assertIs(first, second)

    def test_cedar_schema_json_has_expected_top_level_namespaces(self):
        schema = engine.cedar_schema_json
        # "" is the global namespace. Inventory is the most-exercised
        # contrib namespace in this codebase.
        self.assertIn("", schema)
        self.assertIn("Inventory", schema)
        # Both ``entityTypes`` and ``actions`` keys must be present per
        # namespace (cedarpy rejects schemas otherwise).
        for ns_block in schema.values():
            self.assertIn("entityTypes", ns_block)
            self.assertIn("actions", ns_block)


class AuthorizeRequestTestCase(TestCase):
    """pbac.cedar.authorize_request smoke: a legacy-perm request reaches the
    expected decision against the engine schema."""

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            get_random_string(12),
            f"{get_random_string(12)}@zentral.com",
            is_superuser=False,
        )
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.add(cls.group)
        # Permit the group on a single legacy perm by writing a Cedar
        # policy directly. We pick accounts.view_user because it's
        # unambiguously LEGACY_PERM_APPLIES_TO-shaped (System resource,
        # empty context).
        Policy.objects.create(
            name="Tests",
            source=format_policies(
                f'permit (principal in Role::"{cls.group.pk}", '
                f'action == Accounts::Action::"viewUser", resource);'
            ),
        )

    def setUp(self):
        policies_cache.clear()

    def _make_legacy_request(self, perm):
        return Request(
            Principal.from_user(self.user),
            engine.legacy_perm_actions[perm],
            engine.system_any_resource,
        )

    def test_authorize_legacy_request_granted(self):
        req = self._make_legacy_request("accounts.view_user")
        authorize_request(req)
        self.assertTrue(req.is_authorized)

    def test_authorize_unmatched_legacy_request_denied(self):
        # An action this group's policy doesn't grant.
        req = self._make_legacy_request("accounts.delete_user")
        authorize_request(req)
        self.assertFalse(req.is_authorized)


class HasLegacyPermTestCase(TestCase):
    """Engine.has_legacy_perm integration smoke."""

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            get_random_string(12),
            f"{get_random_string(12)}@zentral.com",
            is_superuser=False,
        )
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.add(cls.group)
        Policy.objects.create(
            name="Tests",
            source=format_policies(
                f'permit (principal in Role::"{cls.group.pk}", '
                f'action == Inventory::Action::"createMachineTag", resource);'
            ),
        )

    def setUp(self):
        policies_cache.clear()
        # Clear the per-user legacy perm cache that has_legacy_perm builds.
        for attr in ("_pbac_legacy_perms", "_pbac_module_legacy_perms", "_pbac_principal"):
            if hasattr(self.user, attr):
                delattr(self.user, attr)

    def test_has_legacy_perm_grants_when_policy_matches(self):
        self.assertTrue(engine.has_legacy_perm(self.user, "inventory.add_machinetag"))

    def test_has_legacy_perm_denies_when_no_policy_matches(self):
        # The seed policy only covers add_machinetag; delete_machinetag must deny.
        self.assertFalse(engine.has_legacy_perm(self.user, "inventory.delete_machinetag"))

    def test_has_legacy_perm_unknown_perm_denies(self):
        self.assertFalse(engine.has_legacy_perm(self.user, "foo.bar_baz"))


class SerializeRequestsEntitiesTestCase(SerializeMixin, TestCase):
    """Cedar scopes entity types and action ids to their namespace, so the
    entities of a batch are collected per namespaced type."""

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            get_random_string(12),
            f"{get_random_string(12)}@zentral.com",
            is_superuser=False,
        )

    def test_same_type_name_in_two_namespaces(self):
        principal = Principal.from_user(self.user)
        requests = []
        for namespace_id in ("NsOne", "NsTwo"):
            namespace = Namespace(namespace_id)
            requests.append(Request(
                principal,
                Action("look", namespace),
                Resource("Widget", "5", namespace, [Resource("Container", "7", namespace)]),
            ))
        _, entities = self.serialize(requests)
        for namespace_id in ("NsOne", "NsTwo"):
            self.assertIn((f"{namespace_id}::Action", "look"), entities)
            self.assertEqual(
                entities[(f"{namespace_id}::Widget", "5")]["parents"],
                [{"type": f"{namespace_id}::Container", "id": "7"}],
            )

    def test_action_groups_of_two_namespaces(self):
        principal = Principal.from_user(self.user)
        _, entities = self.serialize([
            Request(principal, engine.legacy_perm_actions[perm], engine.system_any_resource)
            for perm in ("accounts.view_user", "inventory.add_machinetag")
        ])
        # every namespace registers its own action groups, under the same ids
        self.assertIn(("Accounts::Action", "AdminActions"), entities)
        self.assertIn(("Inventory::Action", "AdminActions"), entities)
        self.assertIn(("Action", "GlobalAdminActions"), entities)


class PBACCedarPreviewTestCase(TestCase):
    """authorize_request_preview: the answer when the context is not known yet.

    forceCleanSync is the fixture because its context attributes are required, which is the case
    the preview exists for. full_clean keeps a test from resting on a policy nobody could save.
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            get_random_string(12),
            f"{get_random_string(12)}@zentral.com",
            is_superuser=False,
        )
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.add(cls.group)
        cls.action = engine.get_action("forceCleanSync", engine.get_namespace("Santa"))
        cls.machine = Resource("Machine", "0123456789", INVENTORY)

    def setUp(self):
        policies_cache.clear()
        if hasattr(self.user, "_pbac_principal"):
            del self.user._pbac_principal

    def _policy(self, source):
        Policy.objects.filter(name="Tests").delete()
        policy = Policy(name="Tests", source=format_policies(source))
        # the check an operator gets on the policy form
        policy.full_clean()
        policy.save()
        policies_cache.clear()

    def _request(self, unknown_context, context=None, resource=None):
        return Request(
            Principal.from_user(self.user),
            self.action,
            resource if resource is not None else self.machine,
            context,
            unknown_context=unknown_context,
        )

    def _full_context(self, sync_type="CLEAN_ALL"):
        return {"syncType": sync_type, "configurationName": "Default", "configurationID": 1}

    def _clean_sync_policy(self, sync_type="CLEAN_ALL"):
        self._policy(f'permit (principal in Role::"{self.group.pk}", '
                     f'action == Santa::Action::"forceCleanSync", resource) '
                     f'when {{ context.syncType == "{sync_type}" }};')

    def test_preview_is_not_refused_by_a_condition_it_cannot_evaluate(self):
        # a policy that reads a key with no value yet must not turn the preview into a refusal
        self._clean_sync_policy()
        request = self._request(unknown_context=True)
        engine.authorize_request(request)
        self.assertTrue(request.is_authorized)

    def test_the_same_condition_refuses_a_full_request_that_does_not_match(self):
        self._clean_sync_policy()
        request = self._request(unknown_context=False, context=self._full_context("CLEAN"))
        engine.authorize_request(request)
        self.assertFalse(request.is_authorized)

    def test_the_same_condition_grants_a_full_request_that_matches(self):
        self._clean_sync_policy()
        request = self._request(unknown_context=False, context=self._full_context())
        engine.authorize_request(request)
        self.assertTrue(request.is_authorized)

    def test_preview_is_refused_when_no_policy_matches_at_all(self):
        # no context could make this request pass
        self._policy(f'permit (principal in Role::"{self.group.pk}", '
                     f'action == Santa::Action::"viewEnrolledMachine", resource);')
        request = self._request(unknown_context=True)
        engine.authorize_request(request)
        self.assertFalse(request.is_authorized)

    def test_preview_is_granted_by_an_unconditional_policy(self):
        self._policy(f'permit (principal in Role::"{self.group.pk}", '
                     f'action == Santa::Action::"forceCleanSync", resource);')
        request = self._request(unknown_context=True)
        engine.authorize_request(request)
        self.assertTrue(request.is_authorized)

    def test_a_full_request_with_an_empty_context_is_refused_by_the_same_policy(self):
        # an empty context is not an unknown one: a policy that reads a key from it errors
        self._clean_sync_policy()
        request = self._request(unknown_context=False, context={})
        engine.authorize_request(request)
        self.assertFalse(request.is_authorized)

    def test_a_preview_that_cedar_cannot_evaluate_is_refused(self):
        # Cedar answers NoDecision when it cannot read the request either. A quote in a serial
        # number is enough, and a serial number reaches the resource id from the URL.
        self._policy(f'permit (principal in Role::"{self.group.pk}", '
                     f'action == Santa::Action::"forceCleanSync", resource);')
        request = self._request(unknown_context=True,
                                resource=Resource("Machine", 'AB"CD', INVENTORY))
        with self.assertLogs("zentral.pbac.cedar", level="ERROR") as cm:
            engine.authorize_request(request)
        self.assertFalse(request.is_authorized)
        self.assertIn("Cedar errors for", cm.output[0])

    def test_a_full_request_that_cedar_cannot_evaluate_is_refused_and_logged(self):
        self._policy(f'permit (principal in Role::"{self.group.pk}", '
                     f'action == Santa::Action::"forceCleanSync", resource);')
        request = self._request(unknown_context=False, context=self._full_context(),
                                resource=Resource("Machine", 'AB"CD', INVENTORY))
        with self.assertLogs("zentral.pbac.cedar", level="ERROR") as cm:
            engine.authorize_request(request)
        self.assertFalse(request.is_authorized)
        self.assertIn("Cedar errors for", cm.output[0])

    def test_batch_mixes_previews_and_full_requests(self):
        self._clean_sync_policy()
        preview = self._request(unknown_context=True)
        matching = self._request(unknown_context=False, context=self._full_context())
        other = self._request(unknown_context=False, context=self._full_context("CLEAN"))
        engine.authorize_requests([preview, matching, other])
        self.assertEqual([preview.is_authorized, matching.is_authorized, other.is_authorized],
                         [True, True, False])

    def test_a_batch_leaves_a_request_that_is_already_answered_alone(self):
        # answered in __init__, so it must not go to Cedar at all
        superuser = User.objects.create_user(
            get_random_string(12), f"{get_random_string(12)}@zentral.com", is_superuser=True)
        self._policy('forbid (principal, action, resource);')
        answered = Request(Principal.from_user(superuser), self.action, self.machine)
        pending = self._request(unknown_context=False, context=self._full_context())
        engine.authorize_requests([answered, pending])
        self.assertTrue(answered.is_authorized)
        self.assertFalse(pending.is_authorized)

    def test_a_superuser_short_circuits_before_either_evaluator(self):
        superuser = User.objects.create_user(
            get_random_string(12), f"{get_random_string(12)}@zentral.com", is_superuser=True)
        self._policy('forbid (principal, action, resource);')
        request = Request(
            Principal.from_user(superuser), self.action, self.machine, unknown_context=True,
        )
        self.assertFalse(request.is_pending)
        engine.authorize_request(request)
        self.assertTrue(request.is_authorized)

    def test_a_request_cannot_be_unknown_and_carry_a_context(self):
        with self.assertRaises(ValueError) as cm:
            self._request(unknown_context=True, context=self._full_context())
        self.assertEqual(cm.exception.args[0], "A request with an unknown context cannot carry one")

    def test_the_full_evaluator_refuses_a_preview(self):
        with self.assertRaises(ValueError) as cm:
            authorize_request(self._request(unknown_context=True))
        self.assertEqual(cm.exception.args[0],
                         "A request with an unknown context needs authorize_request_preview")

    def test_the_batch_evaluator_refuses_a_preview(self):
        with self.assertRaises(ValueError) as cm:
            authorize_requests([self._request(unknown_context=True)])
        self.assertEqual(cm.exception.args[0],
                         "A request with an unknown context needs authorize_request_preview")


class PBACGateTestCase(TestCase):
    """A preview is not a decision, so it cannot gate a view."""

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            get_random_string(12), f"{get_random_string(12)}@zentral.com", is_superuser=False)
        cls.action = engine.get_action("forceCleanSync", engine.get_namespace("Santa"))

    def _preview_request(self, user_obj):
        return Request(Principal.from_user(user_obj), self.action,
                       Resource("Machine", "0123456789", INVENTORY), unknown_context=True)

    def test_view_mixin_refuses_a_preview(self):
        test_case = self

        class View(PBACViewMixin):
            def get_pbac_request_kwargs(self, kwargs):
                return {}

            def pbac_request_class(self, user_obj, **kwargs):
                return test_case._preview_request(user_obj)

        request = RequestFactory().get("/")
        request.user = self.user
        with self.assertRaises(ValueError) as cm:
            View().dispatch(request)
        self.assertIn("cannot gate a view", cm.exception.args[0])

    def test_view_mixin_denies_a_full_request_without_a_policy(self):
        test_case = self

        class View(PBACViewMixin):
            def get_pbac_request_kwargs(self, kwargs):
                return {}

            def pbac_request_class(self, user_obj, **kwargs):
                return Request(Principal.from_user(user_obj), test_case.action,
                               Resource("Machine", "0123456789", INVENTORY),
                               {"syncType": "CLEAN_ALL", "configurationName": "D",
                                "configurationID": 1})

        request = RequestFactory().get("/")
        request.user = self.user
        with self.assertRaises(PermissionDenied):
            View().dispatch(request)

    def test_drf_permission_refuses_a_preview(self):
        test_case = self

        class View:
            def get_pbac_request(self, request):
                return test_case._preview_request(request.user)

        request = RequestFactory().get("/")
        request.user = self.user
        with self.assertRaises(ValueError) as cm:
            PBACPermission().has_permission(request, View())
        self.assertIn("cannot gate a view", cm.exception.args[0])


class PBACCedarContextEntityTestCase(SerializeMixin, TestCase):
    """An entity named in a context or an attribute has to be sent to Cedar too.

    Cedar looks it up by id. If it is missing, the policy that reads it errors and is skipped.
    """

    def _request(self, context):
        return Request(
            Principal.from_user(User(username="u", pk=1)),
            engine.legacy_perm_actions["inventory.add_machinetag"],
            engine.system_any_resource,
            context,
        )

    def _slice(self, context):
        serialized_requests, entities = self.serialize([self._request(context)])
        return serialized_requests[0], entities

    def test_an_entity_in_the_context_reaches_the_slice_with_its_attributes(self):
        job = Entity("Job", "j1", attrs={"kind": "file_export"})
        _, entities = self._slice({"job": job})
        self.assertEqual(entities[("Job", "j1")]["attrs"], {"kind": "file_export"})

    def test_an_entity_in_the_context_reaches_the_slice_with_its_parents(self):
        job = Entity("Job", "j1", parents=[Entity("JobGroup", "g1")])
        _, entities = self._slice({"job": job})
        self.assertEqual(entities[("Job", "j1")]["parents"], [{"type": "JobGroup", "id": "g1"}])
        self.assertIn(("JobGroup", "g1"), entities)

    def test_an_entity_nested_in_a_context_record_reaches_the_slice(self):
        _, entities = self._slice({"scope": {"job": Entity("Job", "j1")}})
        self.assertIn(("Job", "j1"), entities)

    def test_entities_in_a_context_list_reach_the_slice(self):
        _, entities = self._slice({"tags": [Entity("Tag", "t1"), Entity("Tag", "t2")]})
        self.assertIn(("Tag", "t1"), entities)
        self.assertIn(("Tag", "t2"), entities)

    def test_an_entity_attribute_of_an_entity_reaches_the_slice_with_its_attributes(self):
        job = Entity("Job", "j1", attrs={"kind": "file_export"})
        row = Entity("OneTimeJob", "o1", attrs={"job": job})
        _, entities = self._slice({"row": row})
        self.assertEqual(entities[("Job", "j1")]["attrs"], {"kind": "file_export"})
        self.assertEqual(entities[("OneTimeJob", "o1")]["attrs"],
                         {"job": {"__entity": {"type": "Job", "id": "j1"}}})

    def test_a_context_entity_is_rendered_as_a_reference(self):
        serialized, _ = self._slice({"job": Entity("Job", "j1")})
        self.assertEqual(serialized["context"],
                         {"job": {"__entity": {"type": "Job", "id": "j1"}}})

    def test_a_context_without_entities_is_unchanged(self):
        serialized, _ = self._slice({"tagName": "yolo", "n": 3, "ok": True})
        self.assertEqual(serialized["context"], {"tagName": "yolo", "n": 3, "ok": True})

    def test_a_value_cedar_has_no_type_for_is_refused(self):
        with self.assertRaises(TypeError) as cm:
            self._slice({"ratio": 1.5})
        self.assertEqual(cm.exception.args[0], "Unsupported value type float")

    def test_a_preview_sends_no_context(self):
        request = Request(
            Principal.from_user(User(username="u", pk=1)),
            engine.legacy_perm_actions["inventory.add_machinetag"],
            engine.system_any_resource,
            unknown_context=True,
        )
        serialized_requests, _ = self.serialize([request])
        self.assertIsNone(serialized_requests[0]["context"])

    def test_a_cycle_between_two_entities_terminates(self):
        left = Entity("Job", "left")
        right = Entity("Job", "right", attrs={"other": left})
        left.attrs["other"] = right
        _, entities = self._slice({"job": left})
        self.assertEqual(entities[("Job", "left")]["attrs"],
                         {"other": {"__entity": {"type": "Job", "id": "right"}}})
        self.assertEqual(entities[("Job", "right")]["attrs"],
                         {"other": {"__entity": {"type": "Job", "id": "left"}}})

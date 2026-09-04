from cedarpy import format_policies, PolicySet
from django.contrib.auth.models import Group
from django.test import TestCase
from django.utils.crypto import get_random_string

from accounts.models import Policy, User
from pbac.cedar import (_serialize_request, _serialize_requests_entities, authorize_request,
                        authorize_requests, PoliciesCache, policies_cache)
from pbac.engine import engine
from pbac.entities import Action, Entity, Namespace, Principal, Request, Resource
from .utils import force_policy


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


class SerializeRequestsEntitiesTestCase(TestCase):
    """Cedar scopes entity types and action ids to their namespace, so the
    entities of a batch are collected per namespaced type."""

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            get_random_string(12),
            f"{get_random_string(12)}@zentral.com",
            is_superuser=False,
        )

    def _serialize(self, requests):
        entities = _serialize_requests_entities(requests)
        uids = [(e["uid"]["type"], e["uid"]["id"]) for e in entities]
        self.assertEqual(len(uids), len(set(uids)))
        # a parent that is missing from the array is an entity without attributes
        # and without parents of its own, and cedar reports no error for it
        for entity in entities:
            for parent in entity["parents"]:
                self.assertIn((parent["type"], parent["id"]), uids)
        return dict(zip(uids, entities))

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
        entities = self._serialize(requests)
        for namespace_id in ("NsOne", "NsTwo"):
            self.assertIn((f"{namespace_id}::Action", "look"), entities)
            self.assertEqual(
                entities[(f"{namespace_id}::Widget", "5")]["parents"],
                [{"type": f"{namespace_id}::Container", "id": "7"}],
            )

    def test_action_groups_of_two_namespaces(self):
        principal = Principal.from_user(self.user)
        entities = self._serialize([
            Request(principal, engine.legacy_perm_actions[perm], engine.system_any_resource)
            for perm in ("accounts.view_user", "inventory.add_machinetag")
        ])
        # every namespace registers its own action groups, under the same ids
        self.assertIn(("Accounts::Action", "AdminActions"), entities)
        self.assertIn(("Inventory::Action", "AdminActions"), entities)
        self.assertIn(("Action", "GlobalAdminActions"), entities)


class PBACCedarPreviewTestCase(TestCase):
    """authorize_request_preview: the partial evaluation behind an unknown context.

    A view that has to decide whether to offer an action cannot always fill in the context — the user
    has not picked the object that would complete it yet. Answering that with a full evaluation would
    force every context attribute to be declared optional and every policy to carry a `has` guard, so
    the request is marked unknown_context and answered by partial evaluation instead.
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

    def setUp(self):
        policies_cache.clear()
        if hasattr(self.user, "_pbac_principal"):
            del self.user._pbac_principal

    def _policy(self, source):
        Policy.objects.update_or_create(name="Tests", defaults={"source": format_policies(source)})
        policies_cache.clear()

    def _request(self, unknown_context, context=None):
        return Request(
            Principal.from_user(self.user),
            engine.legacy_perm_actions["inventory.add_machinetag"],
            engine.system_any_resource,
            context,
            unknown_context=unknown_context,
        )

    def test_preview_is_not_refused_by_a_condition_it_cannot_evaluate(self):
        # the point: a policy reading an attribute the request cannot supply yet must not turn the
        # preview into a refusal
        self._policy(f'permit (principal in Role::"{self.group.pk}", '
                     f'action == Inventory::Action::"createMachineTag", resource) '
                     'when { context.tagName == "yolo" };')
        request = self._request(unknown_context=True)
        engine.authorize_request(request)
        self.assertTrue(request.is_authorized)

    def test_the_same_condition_refuses_a_full_request_that_does_not_match(self):
        self._policy(f'permit (principal in Role::"{self.group.pk}", '
                     f'action == Inventory::Action::"createMachineTag", resource) '
                     'when { context.tagName == "yolo" };')
        request = self._request(unknown_context=False, context={"tagName": "fomo"})
        engine.authorize_request(request)
        self.assertFalse(request.is_authorized)

    def test_preview_is_refused_when_no_policy_matches_at_all(self):
        # Deny is the one definitive answer a preview gives
        self._policy(f'permit (principal in Role::"{self.group.pk}", '
                     f'action == Inventory::Action::"deleteMachineTag", resource);')
        request = self._request(unknown_context=True)
        engine.authorize_request(request)
        self.assertFalse(request.is_authorized)

    def test_preview_is_granted_by_an_unconditional_policy(self):
        self._policy(f'permit (principal in Role::"{self.group.pk}", '
                     f'action == Inventory::Action::"createMachineTag", resource);')
        request = self._request(unknown_context=True)
        engine.authorize_request(request)
        self.assertTrue(request.is_authorized)

    def test_a_full_request_with_an_empty_context_is_refused_by_the_same_policy(self):
        # what a preview is NOT: an empty context is a record with no attributes, and reading one
        # fails, which is why the coarse question cannot ride the full evaluator
        self._policy(f'permit (principal in Role::"{self.group.pk}", '
                     f'action == Inventory::Action::"createMachineTag", resource) '
                     'when { context.tagName == "yolo" };')
        request = self._request(unknown_context=False, context={})
        engine.authorize_request(request)
        self.assertFalse(request.is_authorized)

    def test_batch_mixes_previews_and_full_requests(self):
        self._policy(f'permit (principal in Role::"{self.group.pk}", '
                     f'action == Inventory::Action::"createMachineTag", resource) '
                     'when { context.tagName == "yolo" };')
        preview = self._request(unknown_context=True)
        matching = self._request(unknown_context=False, context={"tagName": "yolo"})
        other = self._request(unknown_context=False, context={"tagName": "fomo"})
        engine.authorize_requests([preview, matching, other])
        self.assertEqual([preview.is_authorized, matching.is_authorized, other.is_authorized],
                         [True, True, False])

    def test_a_superuser_short_circuits_before_either_evaluator(self):
        superuser = User.objects.create_user(
            get_random_string(12), f"{get_random_string(12)}@zentral.com", is_superuser=True)
        request = Request(
            Principal.from_user(superuser),
            engine.legacy_perm_actions["inventory.add_machinetag"],
            engine.system_any_resource,
            unknown_context=True,
        )
        self.assertFalse(request.is_pending)
        self.assertTrue(request.is_authorized)


class PBACCedarContextEntityTestCase(TestCase):
    """An entity named in a context or an attribute has to reach the entity slice.

    Cedar dereferences ``context.job.kind`` against the store it is given. An entity that is not
    there fails the dereference, which turns a forbid into an allow with nothing but a diagnostic —
    so the walk that collects them is load-bearing, not a convenience.
    """

    def _entity(self, type_name, id, attrs=None, parents=None):
        return Entity(type_name, id, attrs=attrs or {}, parents=parents or [])

    def _request(self, context):
        return Request(
            Principal.from_user(User(username="u", pk=1)),
            engine.legacy_perm_actions["inventory.add_machinetag"],
            engine.system_any_resource,
            context,
        )

    def _slice(self, request):
        return {(e["uid"]["type"], e["uid"]["id"]) for e in _serialize_requests_entities([request])}

    def test_an_entity_in_the_context_reaches_the_slice(self):
        job = self._entity("Job", "j1", attrs={"kind": "file_export"})
        self.assertIn(("Job", "j1"), self._slice(self._request({"job": job})))

    def test_an_entity_nested_in_a_context_record_reaches_the_slice(self):
        job = self._entity("Job", "j1")
        self.assertIn(("Job", "j1"), self._slice(self._request({"scope": {"job": job}})))

    def test_entities_in_a_context_list_reach_the_slice(self):
        tags = [self._entity("Tag", "t1"), self._entity("Tag", "t2")]
        found = self._slice(self._request({"tags": tags}))
        self.assertIn(("Tag", "t1"), found)
        self.assertIn(("Tag", "t2"), found)

    def test_an_entity_attribute_of_an_entity_reaches_the_slice(self):
        job = self._entity("Job", "j1")
        row = self._entity("OneTimeJob", "o1", attrs={"job": job})
        self.assertIn(("Job", "j1"), self._slice(self._request({"row": row})))

    def test_a_context_entity_is_rendered_as_a_reference(self):
        job = self._entity("Job", "j1")
        serialized = _serialize_request(self._request({"job": job}))
        self.assertEqual(serialized["context"],
                         {"job": {"__entity": {"type": "Job", "id": "j1"}}})

    def test_a_context_without_entities_is_unchanged(self):
        serialized = _serialize_request(self._request({"tagName": "yolo", "n": 3}))
        self.assertEqual(serialized["context"], {"tagName": "yolo", "n": 3})

    def test_a_preview_sends_no_context_even_when_one_was_built(self):
        request = Request(
            Principal.from_user(User(username="u", pk=1)),
            engine.legacy_perm_actions["inventory.add_machinetag"],
            engine.system_any_resource,
            unknown_context=True,
        )
        self.assertIsNone(_serialize_request(request)["context"])

    def test_a_cycle_between_two_entities_terminates(self):
        left = self._entity("Job", "left")
        right = self._entity("Job", "right", attrs={"other": left})
        left.attrs["other"] = right
        found = self._slice(self._request({"job": left}))
        self.assertIn(("Job", "left"), found)
        self.assertIn(("Job", "right"), found)

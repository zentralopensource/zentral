from cedarpy import format_policies
from django.contrib.auth.models import Group
from django.test import TestCase
from django.utils.crypto import get_random_string

from accounts.models import Policy, User
from pbac.cedar import authorize_request, authorize_requests, PoliciesCache, policies_cache
from pbac.engine import engine
from pbac.entities import Principal, Request
from .utils import force_policy


class PBACCedarTestCase(TestCase):
    def test_authorize_requests_no_requests(self):
        self.assertIsNone(authorize_requests([], engine.cedar_schema_json))

    def test_policies_cache_with_sync(self):
        force_policy()
        pc = PoliciesCache(with_sync=True)
        self.assertFalse(pc._sync_started)
        self.assertIsNone(pc._last_refresh_ts)
        # not cached
        self.assertEqual(
            pc.all_policies_concatenated,
            format_policies('permit (principal in Role::"0", action, resource);').strip(),
        )
        self.assertTrue(pc._sync_started)
        ts = pc._last_refresh_ts
        self.assertIsNotNone(ts)
        # cached
        self.assertEqual(
            pc.all_policies_concatenated,
            format_policies('permit (principal in Role::"0", action, resource);').strip(),
        )
        self.assertEqual(ts, pc._last_refresh_ts)
        # clear
        pc.clear()
        self.assertIsNone(pc._concatenated_policies)


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
        authorize_request(req, engine.cedar_schema_json)
        self.assertTrue(req.is_authorized)

    def test_authorize_unmatched_legacy_request_denied(self):
        # An action this group's policy doesn't grant.
        req = self._make_legacy_request("accounts.delete_user")
        authorize_request(req, engine.cedar_schema_json)
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

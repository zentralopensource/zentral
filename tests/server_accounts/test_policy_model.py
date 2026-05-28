from unittest.mock import patch
from django.apps import apps
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils.crypto import get_random_string

from accounts.models import Policy
from accounts.provisioning import PolicyProvisioner
from .utils import force_policy, force_role


class PolicyModelTestCase(TestCase):
    def test_clean_formats_valid_source(self):
        p = Policy(name=get_random_string(12), source='permit (principal,action,resource);')
        p.clean()
        # canonical formatting from cedarpy.format_policies
        self.assertEqual(p.source, 'permit (principal, action, resource);\n')

    def test_clean_invalid_source_surfaces_cedar_error(self):
        p = Policy(name=get_random_string(12), source='permit (')
        with self.assertRaises(ValidationError) as ctx:
            p.clean()
        self.assertEqual(
            ctx.exception.message_dict,
            {"source": ["Invalid CEDAR policy: unexpected end of input"]},
        )

    def test_clean_invalid_effect_surfaces_cedar_error(self):
        p = Policy(name=get_random_string(12), source='allow (principal, action, resource);')
        with self.assertRaises(ValidationError) as ctx:
            p.clean()
        self.assertEqual(
            ctx.exception.message_dict,
            {"source": ["Invalid CEDAR policy: invalid policy effect: allow"]},
        )

    # Schema validation in clean()

    def test_clean_rejects_unknown_action(self):
        p = Policy(
            name=get_random_string(12),
            source='permit (principal, action == Inventory::Action::"crteateMachineTag", resource);',
        )
        with self.assertRaises(ValidationError) as ctx:
            p.clean()
        # cedarpy surfaces the offending action by name in the error.
        message = ctx.exception.message_dict["source"][0]
        self.assertIn("crteateMachineTag", message)
        self.assertIn("unrecognized action", message)

    def test_clean_rejects_unknown_entity_type(self):
        p = Policy(
            name=get_random_string(12),
            source='permit (principal == Bogus::"x", action, resource);',
        )
        with self.assertRaises(ValidationError) as ctx:
            p.clean()
        self.assertIn(
            "Invalid CEDAR policy",
            ctx.exception.message_dict["source"][0],
        )

    def test_clean_accepts_valid_action_reference(self):
        # createMachineTag is registered by inventory/pbac.py; this policy
        # must pass schema validation.
        p = Policy(
            name=get_random_string(12),
            source='permit (principal in Role::"7", action == Inventory::Action::"createMachineTag", resource);',
        )
        p.clean()
        self.assertIn('Inventory::Action::"createMachineTag"', p.source)

    def test_clean_accepts_global_action_group_reference(self):
        p = Policy(
            name=get_random_string(12),
            source='permit (principal in Role::"7", action in Action::"GlobalAdminActions", resource);',
        )
        p.clean()
        self.assertIn('Action::"GlobalAdminActions"', p.source)

    # PolicyManager.referencing_role / referencing_user

    def test_referencing_role_finds_policies_quoting_the_pk(self):
        # Insertion order on purpose differs from the expected name order
        # so the assertion catches a missing order_by.
        Policy.objects.create(name="zeta", source='permit (principal in Role::"42", action, resource);')
        Policy.objects.create(name="alpha", source='permit (principal in Role::"42", action, resource);')
        Policy.objects.create(name="r-7", source='permit (principal in Role::"7", action, resource);')
        Policy.objects.create(name="user", source='permit (principal == User::"42", action, resource);')
        qs = Policy.objects.referencing_role(42)
        self.assertEqual([p.name for p in qs], ["alpha", "zeta"])

    def test_referencing_role_does_not_match_prefix_substring(self):
        # Role::"7" must not match against a substring of Role::"72" —
        # the trailing quote keeps them distinct.
        Policy.objects.create(name="r-72", source='permit (principal in Role::"72", action, resource);')
        self.assertFalse(Policy.objects.referencing_role(7).exists())

    def test_referencing_user_matches_user_and_service_account(self):
        # Insertion order on purpose differs from the expected name order
        # so the assertion catches a missing order_by.
        Policy.objects.create(name="u-1", source='permit (principal == User::"1", action, resource);')
        Policy.objects.create(name="sa-1", source='permit (principal == ServiceAccount::"1", action, resource);')
        Policy.objects.create(name="u-2", source='permit (principal == User::"2", action, resource);')
        qs = Policy.objects.referencing_user(1)
        self.assertEqual([p.name for p in qs], ["sa-1", "u-1"])

    def test_serialize_for_event_keys_only(self):
        p = force_policy()
        self.assertEqual(
            p.serialize_for_event(keys_only=True),
            {'name': p.name, 'pk': str(p.pk)},
        )

    def test_serialize_for_event_provisioning_uid(self):
        p = force_policy(provisioning_uid="puid")
        self.assertEqual(
            p.serialize_for_event(),
            {'created_at': p.created_at,
             'description': p.description,
             'is_active': True,
             'name': p.name,
             'pk': str(p.pk),
             'provisioning_uid': 'puid',
             'source': 'permit (\n  principal in Role::"0",\n  action,\n  resource\n);\n',
             'type': Policy.Type.CEDAR,
             'updated_at': p.updated_at}
        )

    @patch("base.notifier.Notifier.send_notification")
    def test_provisioner_create_policy(self, send_notification):
        rpuid = get_random_string(6)
        role = force_role(provisioning_uid=rpuid)
        puid = get_random_string(6)
        name = get_random_string(12)
        qs = Policy.objects.filter(name=name)
        self.assertEqual(qs.count(), 0)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            PolicyProvisioner(
                apps.get_app_config("accounts"),
                {"apps": {
                     "accounts": {
                         "provisioning": {
                             "policies": {
                                 puid: {
                                     "name": name,
                                     "description": "yolo desc",
                                     "source": "permit (\n"
                                               f"  principal in Role::\"{rpuid}\",\n"
                                               "  action in Action::\"GlobalAdminActions\",\n"
                                               "  resource\n"
                                               ");"
                                  }
                             }
                         }
                     }
                 }}
            ).apply()
        self.assertEqual(qs.count(), 1)
        p = qs.first()
        self.assertEqual(p.provisioning_uid, puid)
        self.assertEqual(p.name, name)
        self.assertEqual(len(callbacks), 1)
        self.assertIn(f'Role::"{role.pk}"', p.source)
        send_notification.assert_called_once_with("policies.change")

    @patch("base.notifier.Notifier.send_notification")
    def test_provisioner_create_policy_invalid_source(self, send_notification):
        puid = get_random_string(6)
        name = get_random_string(12)
        qs = Policy.objects.filter(name=name)
        self.assertEqual(qs.count(), 0)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            PolicyProvisioner(
                apps.get_app_config("accounts"),
                {"apps": {
                     "accounts": {
                         "provisioning": {
                             "policies": {
                                 puid: {
                                     "name": name,
                                     "description": "yolo desc",
                                     "source": "permit ("  # bad
                                  }
                             }
                         }
                     }
                 }}
            ).apply()
        self.assertEqual(qs.count(), 0)
        self.assertEqual(len(callbacks), 0)
        send_notification.assert_not_called()

    @patch("base.notifier.Notifier.send_notification")
    def test_provisioner_update_policy(self, send_notification):
        rpuid = get_random_string(6)
        role = force_role(provisioning_uid=rpuid)
        puid = get_random_string(6)
        policy = force_policy(provisioning_uid=puid)
        qs = Policy.objects.filter(provisioning_uid=puid)
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first(), policy)
        name = get_random_string(12)
        description = get_random_string(12)
        source = (
            "permit (\n"
            f"  principal in Role::\"{rpuid}\",\n"
            "  action in Action::\"GlobalAdminActions\",\n"
            "  resource\n"
            ");"
        )
        self.assertNotEqual(policy.name, name)
        self.assertNotEqual(policy.source, source)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            PolicyProvisioner(
                apps.get_app_config("accounts"),
                {"apps": {
                     "accounts": {
                         "provisioning": {
                             "policies": {
                                 puid: {
                                     "name": name,
                                     "description": description,
                                     "source": source,
                                  }
                             }
                         }
                     }
                 }}
            ).apply()
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first(), policy)
        policy.refresh_from_db()
        self.assertEqual(policy.name, name)
        self.assertEqual(policy.description, description)
        self.assertIn(f'Role::"{role.pk}"', policy.source)
        self.assertEqual(len(callbacks), 1)
        send_notification.assert_called_once_with("policies.change")

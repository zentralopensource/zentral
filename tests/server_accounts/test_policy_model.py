from unittest.mock import patch
from django.apps import apps
from django.test import TestCase
from django.utils.crypto import get_random_string

from accounts.models import Policy
from accounts.provisioning import PolicyProvisioner
from .utils import force_policy, force_role


class PolicyModelTestCase(TestCase):
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
                                               "  action in Action::\"AdminActions\",\n"
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
            "  action in Action::\"AdminActions\",\n"
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

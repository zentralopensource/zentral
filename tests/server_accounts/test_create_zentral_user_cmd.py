import json
from datetime import date, timedelta
from io import StringIO
from unittest.mock import patch

from accounts.models import APIToken, Group, User
from django.core import mail
from django.core.management import call_command
from django.test import TestCase

from tests.zentral_test_utils.assertions.event_assertions import EventAssertions


class CreateZentralUserTestCase(TestCase, EventAssertions):

    def _create_expected_user_updated_event_serialization(self, prev_user, changed_user, prev_roles=None):
        return {"action": "updated",
                "object": {
                    "model": "accounts.user",
                    "pk": str(prev_user.pk),
                    "new_value": self._create_user_event_serialization(changed_user),
                    "prev_value": self._create_user_event_serialization(prev_user, roles=prev_roles)}}

    def _create_expected_user_created_event_serialization(self, user):
        return {"action": "created",
                "object": {
                    "model": "accounts.user",
                    "pk": str(user.pk),
                    "new_value": self._create_user_event_serialization(user)}}

    def _create_user_event_serialization(self, user, pk=None, roles=None):
        if roles is None:
            roles = [{"pk": group.pk, "name": group.name} for group in user.groups.all()]
        return {
            "pk": user.pk if pk is None else pk,
            "username": user.username,
            "email": user.email,
            "is_remote":  user.is_remote,
            "is_service_account":  user.is_service_account,
            "is_superuser":  user.is_superuser,
            "roles":  roles
        }

    def _create_token_event_serialization(self, user, token):
        return {
            "pk": str(token.pk),
            "name": token.name,
            "user": user.serialize_for_event(),
            "expiry": token.expiry,
            "created_at": token.created_at.isoformat(),
            "hashed_key": token.hashed_key
        }

    def _create_expected_api_token_created_event_serialization(self, user):
        return {
            "action": "created",
            "object": {
                 "model": "accounts.apitoken",
                 "pk": str(user.apitoken_set.first().pk),
                 "new_value": self._create_token_event_serialization(user, user.apitoken_set.first())
              }
        }

    def _user_metadata_object(self, user):
        return {"accounts_user": [str(user.pk)]}

    def _api_token_metadata_object(self, user):
        return {"accounts_api_token": [str(user.apitoken_set.first().pk)]}

    def call_command(self, *args, **kwargs):
        out = StringIO()
        call_command(
            "create_zentral_user",
            *args,
            stdout=out,
            stderr=StringIO(),
            **kwargs,
        )
        return out.getvalue()

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_service_account_superuser(self, post_event):
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            with self.assertRaises(SystemExit) as cm:
                self.call_command("yolo", "fomo@example.com", "--service-account", "--superuser")
        self.assertEqual(cm.exception.code, 5)
        self.assert_no_event_published(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_service_account_send_reset(self, post_event):
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            with self.assertRaises(SystemExit) as cm:
                self.call_command("yolo", "fomo@example.com", "--service-account", "--send-reset")
        self.assertEqual(cm.exception.code, 6)
        self.assert_no_event_published(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_superuser_with_api_token(self, post_event):
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            with self.assertRaises(SystemExit) as cm:
                self.call_command("yolo", "fomo@example.com", "--superuser", "--with-api-token")
        self.assertEqual(cm.exception.code, 8)
        self.assertFalse(User.objects.filter(username="yolo").exists())
        self.assert_no_event_published(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_superuser_with_role(self, post_event):
        Group.objects.create(name="Editor")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            with self.assertRaises(SystemExit) as cm:
                self.call_command("yolo", "fomo@example.com", "--superuser", "--role", "Editor")
        self.assertEqual(cm.exception.code, 9)
        self.assertFalse(User.objects.filter(username="yolo").exists())
        self.assert_no_event_published(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_user_invalid_username(self, post_event):
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            with self.assertRaises(SystemExit) as cm:
                self.call_command(" ", "fomo@example.com")
        self.assertEqual(cm.exception.code, 11)
        self.assert_no_event_published(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_user_invalid_email(self, post_event):
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            with self.assertRaises(SystemExit) as cm:
                self.call_command("yolo", "fomo")
        self.assertEqual(cm.exception.code, 12)
        self.assert_no_event_published(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_user_different_email(self, post_event):
        self.call_command("yolo", "fomo0@example.com")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            with self.assertRaises(SystemExit) as cm:
                self.call_command("yolo", "fomo@example.com")
        self.assertEqual(cm.exception.code, 13)
        self.assert_no_event_published(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_different_user_same_email(self, post_event):
        self.call_command("yolo0", "fomo@example.com")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            with self.assertRaises(SystemExit) as cm:
                self.call_command("yolo", "fomo@example.com")
        self.assertEqual(cm.exception.code, 14)
        self.assert_no_event_published(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_user_unknown_role(self, post_event):
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            with self.assertRaises(SystemExit) as cm:
                self.call_command("yolo", "fomo@example.com", "--role", "Editor")
        self.assertEqual(cm.exception.code, 15)
        self.assertFalse(User.objects.filter(username="yolo").exists())
        self.assert_no_event_published(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_user(self, post_event):
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            result = self.call_command("yolo", "fomo@example.com")
        self.assertTrue(result.startswith("User yolo fomo@example.com create"))
        self.assertIn("Password reset: https://", result)

        user = User.objects.get(email="fomo@example.com")
        self.assert_events_published(1, callbacks, post_event)
        self.assert_is_audit_event(
            self._create_expected_user_created_event_serialization(user),
            self._user_metadata_object(user),
            post_event
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_user_json(self, post_event):
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            result = json.loads(self.call_command("yolo", "fomo@example.com", "--json"))
        self.assertFalse(result["service_account"])
        self.assertFalse(result["superuser"])
        self.assertEqual(result["username"], "yolo")
        self.assertEqual(result["email"], "fomo@example.com")
        self.assertTrue(result["created"])
        self.assertFalse(result["updated"])
        self.assertNotIn("api_token", result)
        self.assertFalse(result["api_token_created"])
        self.assertTrue(result["password_reset_url"].startswith("https://"))

        user = User.objects.get(email="fomo@example.com")
        self.assert_events_published(1, callbacks, post_event)
        self.assert_is_audit_event(
            self._create_expected_user_created_event_serialization(user),
            self._user_metadata_object(user),
            post_event
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_superuser(self, post_event):
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            result = self.call_command("yolo", "fomo@example.com", "--superuser")
        self.assertTrue(result.startswith("Superuser yolo fomo@example.com create"))
        self.assertIn("Password reset: https://", result)

        user = User.objects.get(email="fomo@example.com")
        self.assert_events_published(1, callbacks, post_event)
        self.assert_is_audit_event(
            self._create_expected_user_created_event_serialization(user),
            self._user_metadata_object(user),
            post_event
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_skip_existing(self, post_event):
        self.call_command("yolo", "fomo@example.com")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            with self.assertRaises(SystemExit) as cm:
                self.call_command("yolo", "fomo@example.com", "--skip-if-existing")
        self.assertEqual(cm.exception.code, 0)
        self.assert_no_event_published(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_promote_existing_user(self, post_event):
        self.call_command("yolo", "fomo@example.com")
        user = User.objects.get(email="fomo@example.com")

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            result = self.call_command("yolo", "fomo@example.com", "--superuser")

        super_user = User.objects.get(email="fomo@example.com")
        self.assertTrue(result.startswith("Existing user yolo fomo@example.com promoted to superuser"))
        self.assertTrue(super_user.is_superuser)

        self.assert_events_published(1, callbacks, post_event)
        self.assert_is_audit_event(
            self._create_expected_user_updated_event_serialization(user, super_user),
            self._user_metadata_object(user),
            post_event
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_demote_existing_superuser(self, post_event):
        self.call_command("yolo", "fomo@example.com", "--superuser")
        super_user = User.objects.get(email="fomo@example.com")

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            result = self.call_command("yolo", "fomo@example.com")
        user = User.objects.get(email="fomo@example.com")

        self.assertTrue(result.startswith("Existing superuser yolo fomo@example.com demoted"))
        self.assertFalse(user.is_superuser)

        self.assert_events_published(1, callbacks, post_event)
        self.assert_is_audit_event(
            self._create_expected_user_updated_event_serialization(super_user, user),
            self._user_metadata_object(user),
            post_event
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_existing_user(self, post_event):
        self.call_command("yolo", "fomo@example.com")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            result = self.call_command("yolo", "fomo@example.com")
        self.assertTrue(result.startswith("User yolo fomo@example.com already exists"))
        self.assert_no_event_published(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_existing_superuser(self, post_event):
        self.call_command("yolo", "fomo@example.com", "--superuser")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            result = self.call_command("yolo", "fomo@example.com", "--superuser")
        self.assertTrue(result.startswith("Superuser yolo fomo@example.com already exists"))
        self.assert_no_event_published(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_user_with_role(self, post_event):
        group = Group.objects.create(name="Editor")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            result = self.call_command("yolo", "fomo@example.com", "--role", "Editor")
        self.assertIn("Roles added: Editor", result)

        user = User.objects.get(email="fomo@example.com")
        self.assertEqual(list(user.groups.all()), [group])
        self.assert_events_published(1, callbacks, post_event)
        self.assert_is_audit_event(
            self._create_expected_user_created_event_serialization(user),
            self._user_metadata_object(user),
            post_event
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_user_with_two_roles(self, post_event):
        Group.objects.create(name="Editor")
        Group.objects.create(name="Viewer")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            result = json.loads(
                self.call_command("yolo", "fomo@example.com", "--json", "--role", "Editor", "--role", "Viewer")
            )
        self.assertEqual(result["roles"], ["Editor", "Viewer"])

        user = User.objects.get(email="fomo@example.com")
        self.assertEqual(sorted(user.groups.values_list("name", flat=True)), ["Editor", "Viewer"])
        self.assert_events_published(1, callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_add_role_to_existing_user(self, post_event):
        self.call_command("yolo", "fomo@example.com")
        user = User.objects.get(email="fomo@example.com")
        group = Group.objects.create(name="Editor")

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            result = self.call_command("yolo", "fomo@example.com", "--role", "Editor")
        self.assertTrue(result.startswith("User yolo fomo@example.com already exists"))
        self.assertIn("Roles added: Editor", result)

        updated_user = User.objects.get(email="fomo@example.com")
        self.assertEqual(list(updated_user.groups.all()), [group])
        self.assert_events_published(1, callbacks, post_event)
        self.assert_is_audit_event(
            self._create_expected_user_updated_event_serialization(user, updated_user, prev_roles=[]),
            self._user_metadata_object(user),
            post_event
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_existing_user_existing_role(self, post_event):
        Group.objects.create(name="Editor")
        self.call_command("yolo", "fomo@example.com", "--role", "Editor")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            result = self.call_command("yolo", "fomo@example.com", "--role", "Editor")
        self.assertTrue(result.startswith("User yolo fomo@example.com already exists"))
        self.assertNotIn("Roles added", result)
        self.assert_no_event_published(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_user_with_api_token(self, post_event):
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            result = self.call_command("yolo", "fomo@example.com", "--with-api-token")
        self.assertIn("Created API token", result)

        user = User.objects.get(email="fomo@example.com")
        self.assert_events_published(2, callbacks, post_event)
        self.assert_is_audit_event(
            self._create_expected_user_created_event_serialization(user),
            self._user_metadata_object(user),
            post_event
        )
        self.assert_is_audit_event(
            self._create_expected_api_token_created_event_serialization(user),
            self._api_token_metadata_object(user),
            post_event,
            expected_order=1
        )

    def test_create_user_with_api_token_expiry_format(self):

        with self.assertRaises(SystemExit) as cm:
            result = self.call_command("yolo", "fomo_expiry@example.com",
                                       "--with-api-token", "--api-token-expiry", "Morgen schon abgelaufen")

        self.assertEqual(cm.exception.code, 7)

        expiry_date = date.today() + timedelta(days=1)
        result = self.call_command("yolo", "fomo_expiry@example.com",
                                   "--with-api-token", "--api-token-expiry", expiry_date)
        user = User.objects.get(email="fomo_expiry@example.com")
        self.assertIn(str(user.email), result)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_user_with_api_token_json(self, post_event):
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            result = json.loads(self.call_command("yolo", "fomo@example.com", "--json", "--with-api-token"))
        self.assertEqual(
            APIToken.objects._hash_key(result["api_token"]),
            User.objects.get(email="fomo@example.com").apitoken_set.first().hashed_key
        )
        self.assertTrue(result["api_token_created"])

        user = User.objects.get(email="fomo@example.com")
        self.assert_events_published(2, callbacks, post_event)
        self.assert_is_audit_event(
            self._create_expected_user_created_event_serialization(user),
            self._user_metadata_object(user),
            post_event
        )
        self.assert_is_audit_event(
            self._create_expected_api_token_created_event_serialization(user),
            self._api_token_metadata_object(user),
            post_event,
            expected_order=1
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_user_existing_api_token(self, post_event):
        self.call_command("yolo", "fomo@example.com", "--with-api-token")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            result = self.call_command("yolo", "fomo@example.com", "--with-api-token")
        self.assertIn("Existing API token", result)
        self.assert_no_event_published(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_user_existing_api_token_json(self, post_event):
        self.call_command("yolo", "fomo@example.com", "--json", "--with-api-token")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            result = json.loads(self.call_command("yolo", "fomo@example.com", "--json", "--with-api-token"))
        self.assertNotIn("api_token", result)
        self.assertFalse(result["api_token_created"])
        self.assert_no_event_published(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_user_send_email(self, post_event):
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            self.call_command("yolo", "fomo@example.com", "--send-reset")
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject, "Invitation to Zentral")
        self.assertIn("Your username: yolo", mail.outbox[0].body)

        user = User.objects.get(email="fomo@example.com")
        self.assert_events_published(1, callbacks, post_event)
        self.assert_is_audit_event(
            self._create_expected_user_created_event_serialization(user),
            self._user_metadata_object(user),
            post_event
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_superuser_service_account(self, post_event):
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            result = json.loads(
                self.call_command("yolo", "fomo@example.com", "--service-account", "--json")
            )
        api_token = result.pop("api_token")
        self.assertEqual(
            result,
            {'api_token_created': True,
             'created': True,
             'email': 'fomo@example.com',
             'roles': [],
             'service_account': True,
             'superuser': False,
             'updated': False,
             'username': 'yolo'}
        )
        user = User.objects.get(email='fomo@example.com')
        self.assertEqual(
            APIToken.objects._hash_key(api_token),
            user.apitoken_set.first().hashed_key
        )
        self.assertFalse(user.has_usable_password())
        self.assertTrue(user.is_service_account)
        self.assert_events_published(2, callbacks, post_event)
        self.assert_is_audit_event(
            self._create_expected_user_created_event_serialization(user),
            self._user_metadata_object(user),
            post_event
        )
        self.assert_is_audit_event(
            self._create_expected_api_token_created_event_serialization(user),
            self._api_token_metadata_object(user),
            post_event,
            expected_order=1
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_service_account_with_role(self, post_event):
        group = Group.objects.create(name="Editor")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            result = json.loads(
                self.call_command("yolo", "fomo@example.com", "--service-account", "--role", "Editor", "--json")
            )
        self.assertEqual(result["roles"], ["Editor"])

        user = User.objects.get(email="fomo@example.com")
        self.assertTrue(user.is_service_account)
        self.assertFalse(user.is_superuser)
        self.assertEqual(list(user.groups.all()), [group])
        self.assertEqual(
            APIToken.objects._hash_key(result["api_token"]),
            user.apitoken_set.first().hashed_key
        )
        self.assert_events_published(2, callbacks, post_event)
        self.assert_is_audit_event(
            self._create_expected_user_created_event_serialization(user),
            self._user_metadata_object(user),
            post_event
        )
        self.assert_is_audit_event(
            self._create_expected_api_token_created_event_serialization(user),
            self._api_token_metadata_object(user),
            post_event,
            expected_order=1
        )

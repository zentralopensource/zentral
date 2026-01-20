from io import StringIO
import json
from datetime import timedelta, date
from django.core import mail
from django.core.management import call_command
from django.test import TestCase
from accounts.models import APIToken, User
from unittest.mock import patch
from tests.zentral_test_utils.assertions.event_assertions import EventAssertions


class CreateZentralUserTestCase(TestCase, EventAssertions):

    def _create_expected_user_updated_event_serialization(self, prev_user, changed_user):
        return {"action": "updated",
                "object": {
                    "model": "accounts.user",
                    "pk": str(prev_user.pk),
                    "new_value": self._create_user_event_serialization(changed_user),
                    "prev_value": self._create_user_event_serialization(prev_user)}}

    def _create_expected_user_created_event_serialization(self, user):
        return {"action": "created",
                "object": {
                    "model": "accounts.user",
                    "pk": str(user.pk),
                    "new_value": self._create_user_event_serialization(user)}}

    def _create_user_event_serialization(self, user, pk=None):
        return {
            "pk": user.pk if pk is None else pk,
            "username": user.username,
            "email": user.email,
            "is_remote":  user.is_remote,
            "is_service_account":  user.is_service_account,
            "is_superuser":  user.is_superuser,
            "roles":  [{"pk": group.pk, "name": group.name} for group in user.groups.all()]
        }

    def _create_token_event_serialization(self, user, token):
        return {
            "pk": token.pk,
            "name": token.name,
            "user": user.serialize_for_event(),
            "expiry": token.expiry,
            "created_at": token.created_at,
            "hashed_key": token.hashed_key
        }

    def _create_expected_api_token_created_event_serialization(self, user):
        return {
            "action": "created",
            "object": {
                 "model": "accounts.apitoken",
                 "pk": str(user.api_token.first().pk),
                 "new_value": self._create_token_event_serialization(user, user.api_token.first())
              }
        }

    def _user_metadata_object(self, user):
        return {"accounts_user": [str(user.pk)]}

    def _api_token_metadata_object(self, user):
        return {"accounts_api_token": [str(user.api_token.first().pk)]}

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
        self._assertNoEventPublished(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_service_account_send_reset(self, post_event):
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            with self.assertRaises(SystemExit) as cm:
                self.call_command("yolo", "fomo@example.com", "--service-account", "--send-reset")
        self.assertEqual(cm.exception.code, 6)
        self._assertNoEventPublished(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_user_invalid_username(self, post_event):
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            with self.assertRaises(SystemExit) as cm:
                self.call_command(" ", "fomo@example.com")
        self.assertEqual(cm.exception.code, 11)
        self._assertNoEventPublished(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_user_invalid_email(self, post_event):
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            with self.assertRaises(SystemExit) as cm:
                self.call_command("yolo", "fomo")
        self.assertEqual(cm.exception.code, 12)
        self._assertNoEventPublished(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_user_different_email(self, post_event):
        self.call_command("yolo", "fomo0@example.com")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            with self.assertRaises(SystemExit) as cm:
                self.call_command("yolo", "fomo@example.com")
        self.assertEqual(cm.exception.code, 13)
        self._assertNoEventPublished(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_different_user_same_email(self, post_event):
        self.call_command("yolo0", "fomo@example.com")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            with self.assertRaises(SystemExit) as cm:
                self.call_command("yolo", "fomo@example.com")
        self.assertEqual(cm.exception.code, 14)
        self._assertNoEventPublished(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_user(self, post_event):
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            result = self.call_command("yolo", "fomo@example.com")
        self.assertTrue(result.startswith("User yolo fomo@example.com create"))
        self.assertIn("Password reset: https://", result)

        user = User.objects.get(email="fomo@example.com")
        self._assertEventsPublished(1, callbacks, post_event)
        self._assertIsAuditEvent(
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
        self._assertEventsPublished(1, callbacks, post_event)
        self._assertIsAuditEvent(
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
        self._assertEventsPublished(1, callbacks, post_event)
        self._assertIsAuditEvent(
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
        self._assertNoEventPublished(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_promote_existing_user(self, post_event):
        self.call_command("yolo", "fomo@example.com")
        user = User.objects.get(email="fomo@example.com")

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            result = self.call_command("yolo", "fomo@example.com", "--superuser")

        super_user = User.objects.get(email="fomo@example.com")
        self.assertTrue(result.startswith("Existing user yolo fomo@example.com promoted to superuser"))
        self.assertTrue(super_user.is_superuser)

        self._assertEventsPublished(1, callbacks, post_event)
        self._assertIsAuditEvent(
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

        self._assertEventsPublished(1, callbacks, post_event)
        self._assertIsAuditEvent(
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
        self._assertNoEventPublished(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_existing_superuser(self, post_event):
        self.call_command("yolo", "fomo@example.com", "--superuser")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            result = self.call_command("yolo", "fomo@example.com", "--superuser")
        self.assertTrue(result.startswith("Superuser yolo fomo@example.com already exists"))
        self._assertNoEventPublished(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_user_with_api_token(self, post_event):
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            result = self.call_command("yolo", "fomo@example.com", "--with-api-token")
        self.assertIn("Created API token", result)

        user = User.objects.get(email="fomo@example.com")
        self._assertEventsPublished(2, callbacks, post_event)
        self._assertIsAuditEvent(
            self._create_expected_user_created_event_serialization(user),
            self._user_metadata_object(user),
            post_event
        )
        self._assertIsAuditEvent(
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
            User.objects.get(email="fomo@example.com").api_token.first().hashed_key
        )
        self.assertTrue(result["api_token_created"])

        user = User.objects.get(email="fomo@example.com")
        self._assertEventsPublished(2, callbacks, post_event)
        self._assertIsAuditEvent(
            self._create_expected_user_created_event_serialization(user),
            self._user_metadata_object(user),
            post_event
        )
        self._assertIsAuditEvent(
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
        self._assertNoEventPublished(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_user_existing_api_token_json(self, post_event):
        self.call_command("yolo", "fomo@example.com", "--json", "--with-api-token")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            result = json.loads(self.call_command("yolo", "fomo@example.com", "--json", "--with-api-token"))
        self.assertNotIn("api_token", result)
        self.assertFalse(result["api_token_created"])
        self._assertNoEventPublished(callbacks, post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_user_send_email(self, post_event):
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            self.call_command("yolo", "fomo@example.com", "--send-reset")
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject, "Invitation to Zentral")
        self.assertIn("Your username: yolo", mail.outbox[0].body)

        user = User.objects.get(email="fomo@example.com")
        self._assertEventsPublished(1, callbacks, post_event)
        self._assertIsAuditEvent(
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
             'service_account': True,
             'superuser': False,
             'updated': False,
             'username': 'yolo'}
        )
        user = User.objects.get(email='fomo@example.com')
        self.assertEqual(
            APIToken.objects._hash_key(api_token),
            user.api_token.first().hashed_key
        )
        self.assertFalse(user.has_usable_password())
        self.assertTrue(user.is_service_account)
        self._assertEventsPublished(2, callbacks, post_event)
        self._assertIsAuditEvent(
            self._create_expected_user_created_event_serialization(user),
            self._user_metadata_object(user),
            post_event
        )
        self._assertIsAuditEvent(
            self._create_expected_api_token_created_event_serialization(user),
            self._api_token_metadata_object(user),
            post_event,
            expected_order=1
        )

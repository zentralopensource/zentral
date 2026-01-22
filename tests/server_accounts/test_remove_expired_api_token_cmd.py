from datetime import datetime, timedelta
from io import StringIO
from unittest.mock import patch

from accounts.models import APIToken, User
from django.core.management import call_command
from django.test import TestCase

from tests.zentral_test_utils.assertions.event_assertions import EventAssertions


class RemoveExpiredAPITokenCmdTestCase(TestCase, EventAssertions):
    def call_command(self, *args, **kwargs):
        stdout = StringIO()
        stderr = StringIO()
        call_command(
            "remove_expired_api_tokens",
            *args,
            stdout=stdout,
            stderr=stderr,
            **kwargs,
        )
        return stdout.getvalue(), stderr.getvalue()

    def test_remove_token_no_output(self):
        user = User.objects.create_user("yolo", "fomo@example.com")
        expired_days = 3
        expired_date = datetime.today() - timedelta(days=(expired_days + 1))
        token, api_key = APIToken.objects.create_for_user(user, expiry=expired_date)

        stdout, stderr = self.call_command("-v", 0)

        self.assertEqual("", stdout)
        self.assertTrue(APIToken.objects.filter(id=token.id).exists())

    def test_remove_token_no_token(self):
        user = User.objects.create_user("yolo", "fomo@example.com")
        expired_days = 3
        expired_date = datetime.today() - timedelta(days=(expired_days + 1))
        token, api_key = APIToken.objects.create_for_user(user, expiry=expired_date)

        stdout, stderr = self.call_command()

        self.assertIn("No tokens found", stdout)
        self.assertIn("days since token expired 15", stdout)
        self.assertEqual(stderr, "")
        self.assertTrue(APIToken.objects.filter(id=token.id).exists())

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_remove_one_token(self, post_event):

        user = User.objects.create_user("yolo", "fomo@example.com")
        token_name = "api--token"
        expired_days = 3
        expired_date = datetime.today() - timedelta(days=(expired_days + 1))
        token, api_key = APIToken.objects.create_for_user(
            user, expiry=expired_date, name=token_name
        )

        expected_event_payload = {
            "action": "deleted",
            "object": {
                "model": "accounts.apitoken",
                "pk": str(token.pk),
                "prev_value": token.serialize_for_event(),
            },
        }

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            stdout, stderr = self.call_command("--after-days", expired_days)
        self.assertIn("Tokens to remove:", stdout)
        self.assertIn(token_name, stdout)
        self.assertEqual(stderr, "")
        self.assertFalse(APIToken.objects.filter(id=token.id).exists())

        self._assertEventsPublished(1, callbacks, post_event)
        self._assertIsAuditEvent(
            expected_event_payload, {"accounts_api_token": [str(token.pk)]}, post_event
        )

    def test_remove_token_by_user(self):
        self.maxDiff = None
        user = User.objects.create_user("yolo", "fomo@example.com")
        user2 = User.objects.create_user("yola", "foma@example.com")
        expired_days = 3
        expired_date = datetime.today() - timedelta(days=(expired_days + 1))
        token1_name = "api--token1"
        token1, _ = APIToken.objects.create_for_user(
            user, expiry=expired_date, name=token1_name
        )
        token2_name = "api--token2"
        token2, _ = APIToken.objects.create_for_user(
            user2, expiry=expired_date, name=token2_name
        )
        token3_name = "api--token3"
        token3, _ = APIToken.objects.create_for_user(
            user2, expiry=expired_date, name=token3_name
        )

        stdout, stderr = self.call_command(
            "--after-days", expired_days, "--user", str(user2.username)
        )

        self.assertIn("Tokens to remove", stdout)
        self.assertIn(token2_name, stdout)
        self.assertIn(token3_name, stdout)
        self.assertNotIn(token1_name, stdout)
        self.assertEqual(stderr, "")
        self.assertTrue(APIToken.objects.filter(id=token1.id).exists())

    def test_remove_token_dry_run(self):
        self.maxDiff = None
        user = User.objects.create_user("yolo", "fomo@example.com")
        token_name = "api--token"
        expired_days = 3
        expired_date = datetime.today() - timedelta(days=(expired_days + 1))
        token1, _ = APIToken.objects.create_for_user(
            user, expiry=expired_date, name=token_name
        )

        stdout, stderr = self.call_command("--after-days", expired_days, "--dry-run")

        self.assertIn("Tokens to remove:", stdout)
        self.assertIn(token_name, stdout)
        self.assertEqual(stderr, "")
        self.assertTrue(APIToken.objects.filter(id=token1.id).exists())

    def test_remove_token_json(self):
        self.maxDiff = None
        user = User.objects.create_user("yolo", "fomo@example.com")
        token_name = "api--token"
        expired_days = 3
        expired_date = datetime.today() - timedelta(days=(expired_days + 1))
        token1, _ = APIToken.objects.create_for_user(
            user, expiry=expired_date, name=token_name
        )

        stdout, stderr = self.call_command(
            "--after-days", expired_days, "--dry-run", "--json"
        )

        self.assertIn("token", stdout)
        self.assertIn(token_name, stdout)
        self.assertEqual(stderr, "")
        self.assertTrue(APIToken.objects.filter(id=token1.id).exists())

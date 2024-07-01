from io import StringIO
import json
from django.core import mail
from django.core.management import call_command
from django.test import TestCase
from accounts.models import APIToken, User


class CreateZentralUserTestCase(TestCase):
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

    def test_service_account_superuser(self):
        with self.assertRaises(SystemExit) as cm:
            self.call_command("yolo", "fomo@example.com", "--service-account", "--superuser")
        self.assertEqual(cm.exception.code, 5)

    def test_service_account_send_reset(self):
        with self.assertRaises(SystemExit) as cm:
            self.call_command("yolo", "fomo@example.com", "--service-account", "--send-reset")
        self.assertEqual(cm.exception.code, 6)

    def test_create_user_invalid_username(self):
        with self.assertRaises(SystemExit) as cm:
            self.call_command(" ", "fomo@example.com")
        self.assertEqual(cm.exception.code, 11)

    def test_create_user_invalid_email(self):
        with self.assertRaises(SystemExit) as cm:
            self.call_command("yolo", "fomo")
        self.assertEqual(cm.exception.code, 12)

    def test_create_user_different_email(self):
        self.call_command("yolo", "fomo0@example.com")
        with self.assertRaises(SystemExit) as cm:
            self.call_command("yolo", "fomo@example.com")
        self.assertEqual(cm.exception.code, 13)

    def test_create_different_user_same_email(self):
        self.call_command("yolo0", "fomo@example.com")
        with self.assertRaises(SystemExit) as cm:
            self.call_command("yolo", "fomo@example.com")
        self.assertEqual(cm.exception.code, 14)

    def test_create_user(self):
        result = self.call_command("yolo", "fomo@example.com")
        self.assertTrue(result.startswith("User yolo fomo@example.com create"))
        self.assertIn("Password reset: https://", result)

    def test_create_user_json(self):
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

    def test_create_superuser(self):
        result = self.call_command("yolo", "fomo@example.com", "--superuser")
        self.assertTrue(result.startswith("Superuser yolo fomo@example.com create"))
        self.assertIn("Password reset: https://", result)

    def test_create_skip_existing(self):
        self.call_command("yolo", "fomo@example.com")
        with self.assertRaises(SystemExit) as cm:
            self.call_command("yolo", "fomo@example.com", "--skip-if-existing")
        self.assertEqual(cm.exception.code, 0)

    def test_promote_existing_user(self):
        self.call_command("yolo", "fomo@example.com")
        result = self.call_command("yolo", "fomo@example.com", "--superuser")
        self.assertTrue(result.startswith("Existing user yolo fomo@example.com promoted to superuser"))

    def test_demote_existing_superuser(self):
        self.call_command("yolo", "fomo@example.com", "--superuser")
        result = self.call_command("yolo", "fomo@example.com")
        self.assertTrue(result.startswith("Existing superuser yolo fomo@example.com demoted"))

    def test_existing_user(self):
        self.call_command("yolo", "fomo@example.com")
        result = self.call_command("yolo", "fomo@example.com")
        self.assertTrue(result.startswith("User yolo fomo@example.com already exists"))

    def test_existing_superuser(self):
        self.call_command("yolo", "fomo@example.com", "--superuser")
        result = self.call_command("yolo", "fomo@example.com", "--superuser")
        self.assertTrue(result.startswith("Superuser yolo fomo@example.com already exists"))

    def test_create_user_with_api_token(self):
        result = self.call_command("yolo", "fomo@example.com", "--with-api-token")
        self.assertIn("Created API token", result)

    def test_create_user_with_api_token_json(self):
        result = json.loads(self.call_command("yolo", "fomo@example.com", "--json", "--with-api-token"))
        self.assertEqual(
            APIToken.objects._hash_key(result["api_token"]),
            User.objects.select_related("api_token").get(email="fomo@example.com").api_token.hashed_key
        )
        self.assertTrue(result["api_token_created"])

    def test_create_user_existing_api_token(self):
        self.call_command("yolo", "fomo@example.com", "--with-api-token")
        result = self.call_command("yolo", "fomo@example.com", "--with-api-token")
        self.assertIn("Existing API token", result)

    def test_create_user_existing_api_token_json(self):
        self.call_command("yolo", "fomo@example.com", "--json", "--with-api-token")
        result = json.loads(self.call_command("yolo", "fomo@example.com", "--json", "--with-api-token"))
        self.assertNotIn("api_token", result)
        self.assertFalse(result["api_token_created"])

    def test_create_user_send_email(self):
        self.call_command("yolo", "fomo@example.com", "--send-reset")
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject, "Invitation to Zentral")
        self.assertIn("Your username: yolo", mail.outbox[0].body)

    def test_superuser_service_account(self):
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
            user.api_token.hashed_key
        )
        self.assertFalse(user.has_usable_password())
        self.assertTrue(user.is_service_account)

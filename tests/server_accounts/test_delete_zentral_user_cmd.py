from io import StringIO
from unittest.mock import patch
from django.core.management import call_command
from django.test import TestCase
from accounts.models import APIToken, User


class DeleteZentralUserTestCase(TestCase):
    def call_command(self, *args, **kwargs):
        stdout = StringIO()
        stderr = StringIO()
        call_command(
            "delete_zentral_user",
            *args,
            stdout=stdout,
            stderr=stderr,
            **kwargs,
        )
        return stdout.getvalue(), stderr.getvalue()

    @patch("accounts.management.commands.delete_zentral_user.sys.exit")
    def test_delete_user_zero_users(self, sys_exit):
        stdout, stderr = self.call_command("yolo")
        sys_exit.assert_called_once_with(11)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "0 users deleted\n")

    def test_delete_one_user(self):
        user = User.objects.create_user("yolo", "fomo@example.com")
        APIToken.objects.update_or_create_for_user(user),
        stdout, stderr = self.call_command("yolo")
        self.assertEqual(stdout, "1 user deleted\n")
        self.assertEqual(stderr, "")
        self.assertFalse(User.objects.filter(username="yolo").exists())

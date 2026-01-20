from io import StringIO
from unittest.mock import patch
from django.core.management import call_command
from django.test import TestCase
from accounts.models import APIToken, User
from zentral.core.events.base import AuditEvent


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

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("accounts.management.commands.delete_zentral_user.sys.exit")
    def test_delete_user_zero_users(self, sys_exit, post_event):
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            stdout, stderr = self.call_command("yolo")
        sys_exit.assert_called_once_with(11)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "0 users deleted\n")
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_one_user(self, post_event):
        user = User.objects.create_user("yolo", "fomo@example.com")
        expected_event_payload = {
            "action": "deleted",
            "object": {
                 "model": "accounts.user",
                 "pk": str(user.pk),
                 "prev_value": user.serialize_for_event()
              }
        }
        APIToken.objects.create_for_user(user),
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            stdout, stderr = self.call_command("yolo")
        self.assertEqual(stdout, "1 user deleted\n")
        self.assertEqual(stderr, "")
        self.assertFalse(User.objects.filter(username="yolo").exists())

        self.assertEqual(len(callbacks), 1)
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            expected_event_payload
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"accounts_user": [str(user.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["accounts", "zentral"])

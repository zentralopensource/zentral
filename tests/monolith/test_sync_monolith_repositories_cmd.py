from io import StringIO
from unittest.mock import patch
from django.core.management import call_command
from django.test import TestCase
from .utils import force_repository


class SyncMonolithRepositoriesTestCase(TestCase):
    def call_command(self, *args, **kwargs):
        stdout = StringIO()
        stderr = StringIO()
        call_command(
            "sync_monolith_repositories",
            *args,
            stdout=stdout,
            stderr=stderr,
            **kwargs,
        )
        return stdout.getvalue(), stderr.getvalue()

    @patch("zentral.contrib.monolith.management.commands.sync_monolith_repositories.notifier.send_notification")
    @patch("zentral.contrib.monolith.repository_backends.base.BaseRepository.sync_catalogs")
    def test_sync_error(self, sync_catalogs, send_notification):
        sync_catalogs.side_effect = ValueError("YOLO")
        repository = force_repository()
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            stdout, stderr = self.call_command()
        self.assertEqual(stdout, f"Sync {repository.name} repository\n")
        self.assertEqual(stderr, f"Could not sync {repository.name}: YOLO\n")
        sync_catalogs.assert_called_once()
        self.assertEqual(len(callbacks), 0)
        send_notification.assert_not_called()

    @patch("zentral.contrib.monolith.management.commands.sync_monolith_repositories.notifier.send_notification")
    @patch("zentral.contrib.monolith.repository_backends.base.BaseRepository.sync_catalogs")
    def test_sync_ok(self, sync_catalogs, send_notification):
        repository = force_repository()
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            stdout, stderr = self.call_command()
        self.assertEqual(stdout, f"Sync {repository.name} repository\nOK\n")
        self.assertEqual(stderr, "")
        sync_catalogs.assert_called_once()
        self.assertEqual(len(callbacks), 1)
        send_notification.assert_called_once_with("monolith.repository", str(repository.pk))

    @patch("zentral.contrib.monolith.management.commands.sync_monolith_repositories.notifier.send_notification")
    @patch("zentral.contrib.monolith.repository_backends.base.BaseRepository.sync_catalogs")
    def test_sync_v0_ok(self, sync_catalogs, send_notification):
        repository = force_repository()
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            stdout, stderr = self.call_command("-v0")
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        sync_catalogs.assert_called_once()
        self.assertEqual(len(callbacks), 1)
        send_notification.assert_called_once_with("monolith.repository", str(repository.pk))

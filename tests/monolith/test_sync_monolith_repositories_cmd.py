from io import StringIO
from unittest.mock import call, patch
from django.core.management import call_command
from django.db import connection, connections
from django.test import TestCase
from zentral.contrib.monolith.exceptions import RepositoryError
from zentral.contrib.monolith.models import Catalog, Repository
from zentral.contrib.monolith.tasks import SYNC_REPOSITORY_LOCK_ID
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
    def test_sync_two_repositories_ok(self, sync_catalogs, send_notification):
        force_repository()
        force_repository()
        # the names are random, and the database collation orders them, not python. read the
        # order of the sync from the queryset the command iterates.
        repository1, repository2 = Repository.objects.all()
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            stdout, stderr = self.call_command()
        self.assertEqual(
            stdout,
            f"Sync {repository1.name} repository\nOK\nSync {repository2.name} repository\nOK\n"
        )
        self.assertEqual(stderr, "")
        self.assertEqual(sync_catalogs.call_count, 2)
        self.assertEqual(len(callbacks), 2)
        # the callbacks run after the loop, so each one must carry the pk of its own repository
        self.assertEqual(
            send_notification.call_args_list,
            [call("monolith.repository", str(repository1.pk)),
             call("monolith.repository", str(repository2.pk))]
        )

    @patch("zentral.contrib.monolith.management.commands.sync_monolith_repositories.notifier.send_notification")
    @patch("zentral.contrib.monolith.repository_backends.base.BaseRepository.sync_catalogs")
    def test_sync_already_running(self, sync_catalogs, send_notification):
        repository = force_repository()
        # a second connection is required: advisory locks are only conflicting between sessions
        lock_connection = connections.create_connection("default")
        with lock_connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_lock(%s, %s)", [SYNC_REPOSITORY_LOCK_ID, repository.pk])
        self.addCleanup(lock_connection.close)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            stdout, stderr = self.call_command()
        self.assertEqual(stdout, f"Sync {repository.name} repository\n")
        self.assertEqual(stderr, f"Could not sync {repository.name}: a sync is already running\n")
        sync_catalogs.assert_not_called()
        self.assertEqual(len(callbacks), 0)
        send_notification.assert_not_called()

    @patch("zentral.contrib.monolith.management.commands.sync_monolith_repositories.notifier.send_notification")
    @patch("zentral.contrib.monolith.repository_backends.base.BaseRepository.sync_catalogs")
    def test_sync_error_rolls_the_repository_back(self, sync_catalogs, send_notification):
        repository = force_repository()

        def sync_catalogs_side_effect(*args, **kwargs):
            Catalog.objects.create(repository=repository, name="yolo")
            raise RepositoryError("YOLO")

        sync_catalogs.side_effect = sync_catalogs_side_effect
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            stdout, stderr = self.call_command()
        self.assertEqual(stdout, f"Sync {repository.name} repository\n")
        self.assertEqual(stderr, f"Could not sync {repository.name}: YOLO\n")
        self.assertEqual(len(callbacks), 0)
        send_notification.assert_not_called()
        self.assertFalse(Catalog.objects.filter(repository=repository, name="yolo").exists())

    @patch("zentral.contrib.monolith.management.commands.sync_monolith_repositories.notifier.send_notification")
    @patch("zentral.contrib.monolith.repository_backends.base.BaseRepository.sync_catalogs")
    def test_sync_database_error_on_first_repository(self, sync_catalogs, send_notification):
        force_repository()
        force_repository()
        repository1, repository2 = Repository.objects.all()

        def sync_catalogs_side_effect(*args, **kwargs):
            if sync_catalogs.call_count == 1:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT * FROM monolith_repository_yolo")

        sync_catalogs.side_effect = sync_catalogs_side_effect
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            stdout, stderr = self.call_command()
        # the second repository is synced with a healthy connection
        self.assertEqual(
            stdout,
            f"Sync {repository1.name} repository\nSync {repository2.name} repository\nOK\n"
        )
        self.assertIn(f"Could not sync {repository1.name}:", stderr)
        self.assertEqual(sync_catalogs.call_count, 2)
        self.assertEqual(len(callbacks), 1)
        send_notification.assert_called_once_with("monolith.repository", str(repository2.pk))

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

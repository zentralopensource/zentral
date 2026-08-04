import plistlib
from unittest.mock import patch

from django.db import connections
from django.test import TestCase
from django.utils.crypto import get_random_string

from zentral.contrib.monolith.models import Catalog, PkgInfo, PkgInfoName
from zentral.contrib.monolith.tasks import SYNC_REPOSITORY_LOCK_ID, sync_repository_task
from zentral.core.events.base import AuditEvent

from .utils import force_repository


class MonolithTasksTestCase(TestCase):
    maxDiff = None

    # utility methods

    def _mock_repository_content(self, iter_client_resources, get_icon_hashes_content, get_all_catalog_content):
        catalog_name = get_random_string(12)
        pkg_info_name = get_random_string(12)
        iter_client_resources.return_value = ["site_default.zip",]
        get_icon_hashes_content.return_value = plistlib.dumps({
            f"{pkg_info_name}.png": "a" * 64
        })
        get_all_catalog_content.return_value = plistlib.dumps([
            {"catalogs": [catalog_name],
             "name": pkg_info_name,
             "version": "1.0"}
        ])
        return catalog_name, pkg_info_name

    def _hold_sync_lock(self, repository):
        # a second connection is required: advisory locks are only conflicting between sessions
        lock_connection = connections.create_connection("default")
        with lock_connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_lock(%s, %s)", [SYNC_REPOSITORY_LOCK_ID, repository.pk])
        self.addCleanup(lock_connection.close)

    # sync repository task

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("zentral.contrib.monolith.repository_backends.s3.S3Repository.get_all_catalog_content")
    @patch("zentral.contrib.monolith.repository_backends.s3.S3Repository.get_icon_hashes_content")
    @patch("zentral.contrib.monolith.repository_backends.s3.S3Repository.iter_client_resources")
    def test_sync_repository_task(
        self,
        iter_client_resources,
        get_icon_hashes_content,
        get_all_catalog_content,
        post_event,
        send_notification
    ):
        repository = force_repository()
        catalog_name, pkg_info_name = self._mock_repository_content(
            iter_client_resources, get_icon_hashes_content, get_all_catalog_content
        )
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            result = sync_repository_task(repository.pk)
        self.assertEqual(
            result,
            {"repository": {"pk": repository.pk, "name": repository.name},
             "operations": {"catalog": {"created": 1},
                            "pkginfoname": {"created": 1},
                            "pkginfo": {"created": 1}},
             "status": "SUCCESS"}
        )
        pkg_infos = PkgInfo.objects.filter(name__name=pkg_info_name)
        self.assertEqual(pkg_infos.count(), 1)
        pkg_info = pkg_infos.first()
        self.assertEqual(pkg_info.repository, repository)
        self.assertEqual(list(c.name for c in pkg_info.catalogs.filter(repository=repository)),
                         [catalog_name])
        repository.refresh_from_db()
        self.assertEqual(repository.client_resources, ["site_default.zip"])
        self.assertEqual(repository.icon_hashes, {f"icon.{pkg_info.pk}.{pkg_info_name}.png": "a" * 64})
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(len(post_event.call_args_list), 3)
        mca_evt = post_event.call_args_list[0].args[0]
        self.assertIsInstance(mca_evt, AuditEvent)
        self.assertEqual(mca_evt.payload["action"], "created")
        self.assertEqual(mca_evt.payload["object"]["model"], "monolith.catalog")
        self.assertEqual(mca_evt.payload["object"]["pk"],
                         str(Catalog.objects.get(name=catalog_name).pk))
        mpina_evt = post_event.call_args_list[1].args[0]
        self.assertIsInstance(mpina_evt, AuditEvent)
        self.assertEqual(mpina_evt.payload["action"], "created")
        self.assertEqual(mpina_evt.payload["object"]["model"], "monolith.pkginfoname")
        self.assertEqual(mpina_evt.payload["object"]["pk"],
                         str(PkgInfoName.objects.get(name=pkg_info_name).pk))
        mpia_evt = post_event.call_args_list[2].args[0]
        self.assertIsInstance(mpia_evt, AuditEvent)
        self.assertEqual(mpia_evt.payload["action"], "created")
        self.assertEqual(mpia_evt.payload["object"]["model"], "monolith.pkginfo")
        self.assertEqual(mpia_evt.payload["object"]["pk"], str(pkg_info.pk))
        send_notification.assert_called_once_with("monolith.repository", str(repository.pk))

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("zentral.contrib.monolith.repository_backends.s3.S3Repository.get_all_catalog_content")
    @patch("zentral.contrib.monolith.repository_backends.s3.S3Repository.get_icon_hashes_content")
    @patch("zentral.contrib.monolith.repository_backends.s3.S3Repository.iter_client_resources")
    def test_sync_repository_task_serialized_event_request(
        self,
        iter_client_resources,
        get_icon_hashes_content,
        get_all_catalog_content,
        post_event,
        send_notification
    ):
        repository = force_repository()
        self._mock_repository_content(
            iter_client_resources, get_icon_hashes_content, get_all_catalog_content
        )
        username = get_random_string(12)
        serialized_event_request = {
            "user_agent": "Zentral/tests",
            "ip": "127.0.0.1",
            "method": "POST",
            "path": f"/api/monolith/repositories/{repository.pk}/sync/",
            "view": "monolith_api:sync_repository",
            "user": {"id": 42, "username": username},
        }
        with self.captureOnCommitCallbacks(execute=True):
            result = sync_repository_task(repository.pk, serialized_event_request)
        self.assertEqual(result["status"], "SUCCESS")
        for call in post_event.call_args_list:
            metadata = call.args[0].metadata.serialize()
            self.assertEqual(metadata["request"]["user"]["username"], username)
            self.assertEqual(metadata["request"]["ip"], "127.0.0.1")

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("zentral.contrib.monolith.repository_backends.s3.S3Repository.get_all_catalog_content")
    def test_sync_repository_task_skipped(self, get_all_catalog_content, post_event, send_notification):
        repository = force_repository()
        self._hold_sync_lock(repository)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            result = sync_repository_task(repository.pk)
        self.assertEqual(
            result,
            {"repository": {"pk": repository.pk, "name": repository.name},
             "status": "SKIPPED"}
        )
        get_all_catalog_content.assert_not_called()
        self.assertEqual(PkgInfo.objects.filter(repository=repository).count(), 0)
        self.assertEqual(len(callbacks), 0)
        post_event.assert_not_called()
        send_notification.assert_not_called()

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("zentral.contrib.monolith.repository_backends.s3.S3Repository.get_all_catalog_content")
    @patch("zentral.contrib.monolith.repository_backends.s3.S3Repository.get_icon_hashes_content")
    @patch("zentral.contrib.monolith.repository_backends.s3.S3Repository.iter_client_resources")
    def test_sync_repository_task_lock_is_per_repository(
        self,
        iter_client_resources,
        get_icon_hashes_content,
        get_all_catalog_content,
        post_event,
        send_notification
    ):
        self._hold_sync_lock(force_repository())
        repository = force_repository()
        self._mock_repository_content(
            iter_client_resources, get_icon_hashes_content, get_all_catalog_content
        )
        with self.captureOnCommitCallbacks(execute=True):
            result = sync_repository_task(repository.pk)
        self.assertEqual(result["status"], "SUCCESS")
        send_notification.assert_called_once_with("monolith.repository", str(repository.pk))

from contextlib import contextmanager
from datetime import timedelta
from unittest.mock import patch
from django.db import IntegrityError, connection
from django.test import TestCase
from django.utils import timezone
from zentral.conf import ConfigDict
from zentral.contrib.inventory.models import MachineSnapshot, MachineSnapshotCommit, OSXAppInstance
from zentral.contrib.inventory.utils.cleanup import (MAX_ATTEMPTS, cleanup_inventory, get_cleanup_max_date,
                                                    get_default_snapshot_retention_days)
from .utils import create_ms


class CleanupCursor:
    # a real cursor that records the deleted batches, and can raise an IntegrityError on the
    # first executions of one table query to exercise the retries without a concurrent writer
    def __init__(self, fail_on=None, times=0):
        self.fail_on = fail_on
        self.times = times
        self.failures = 0
        self.query = None
        self.batches = []

    def __enter__(self):
        self.ctx = connection.cursor()
        self.cursor = self.ctx.__enter__()
        return self

    def __exit__(self, *args):
        return self.ctx.__exit__(*args)

    def execute(self, query, params=None):
        self.query = query
        if self.fail_on and f"DELETE FROM {self.fail_on} " in query and self.failures < self.times:
            self.failures += 1
            raise IntegrityError("boom")
        return self.cursor.execute(query, params)

    def fetchall(self):
        rows = self.cursor.fetchall()
        if "DELETE FROM inventory_machinesnapshotcommit" in self.query:
            self.batches.append([row[0] for row in rows])
        return rows


class InventoryCleanupTest(TestCase):
    def cleanup(self, days=30, batch_size=1000, cursor=None):
        results = {}
        max_date = timezone.now() - timedelta(days=days)
        if cursor is not None:
            duration = cleanup_inventory(cursor, results.__setitem__, max_date, batch_size=batch_size)
        else:
            with connection.cursor() as new_cursor:
                duration = cleanup_inventory(new_cursor, results.__setitem__, max_date, batch_size=batch_size)
        return results, duration

    def force_orphan_osx_app_instances(self, count):
        pks = []
        for i in range(count):
            osx_app_instance, _ = OSXAppInstance.objects.commit({
                "bundle_path": f"/Applications/Yolo{i}.app",
                "app": {"bundle_id": "io.zentral.yolo", "bundle_name": f"Yolo{i}", "bundle_version_str": "1.0"},
            })
            pks.append(osx_app_instance.pk)
        return pks

    def force_machine_snapshot_commits(self, count, days):
        commit = MachineSnapshotCommit.objects.get()
        commits = [commit]
        for version in range(2, count + 2):
            commits.append(
                MachineSnapshotCommit.objects.create(
                    serial_number=commit.serial_number,
                    source=commit.source,
                    version=version,
                    machine_snapshot=commit.machine_snapshot,
                    parent=commits[-1],
                )
            )
        # created_at is auto_now_add, it can only be set with an update. Each commit needs
        # a distinct one: the cutoff is a strict comparison with the newest of the group.
        for idx, commit in enumerate(commits):
            MachineSnapshotCommit.objects.filter(pk=commit.pk).update(
                created_at=timezone.now() - timedelta(days=days, hours=len(commits) - idx)
            )
        return [c.pk for c in commits[:-1]], commits[-1].pk

    @contextmanager
    def inventory_conf(self, **conf):
        # the retention is read from the zentral configuration, not from the django settings
        with patch("zentral.contrib.inventory.utils.cleanup.settings") as settings:
            settings.__getitem__.return_value = ConfigDict({"zentral.contrib.inventory": conf})
            yield

    def assertDaysAgo(self, max_date, days, not_before):
        self.assertTrue(not_before - timedelta(days=days) <= max_date <= timezone.now() - timedelta(days=days))

    # retention

    def test_default_snapshot_retention_days(self):
        with self.inventory_conf(snapshot_retention_days="7"):
            self.assertEqual(get_default_snapshot_retention_days(), 7)

    def test_default_snapshot_retention_days_absent(self):
        with self.inventory_conf():
            self.assertEqual(get_default_snapshot_retention_days(), 30)

    def test_default_snapshot_retention_days_bad_value(self):
        with self.inventory_conf(snapshot_retention_days="yolo"):
            with self.assertLogs("zentral.contrib.inventory.utils.cleanup", level="ERROR") as cm:
                self.assertEqual(get_default_snapshot_retention_days(), 30)
        self.assertEqual(cm.records[0].getMessage(),
                         "Wrong value set snapshot_retention_days, default of 30 used")

    def test_default_snapshot_retention_days_minimum(self):
        with self.inventory_conf(snapshot_retention_days="0"):
            self.assertEqual(get_default_snapshot_retention_days(), 1)

    # max date

    def test_cleanup_max_date_defaults_to_the_configured_retention(self):
        not_before = timezone.now()
        with self.inventory_conf(snapshot_retention_days="7"):
            max_date = get_cleanup_max_date()
        self.assertDaysAgo(max_date, 7, not_before)

    def test_cleanup_max_date_days(self):
        not_before = timezone.now()
        self.assertDaysAgo(get_cleanup_max_date(3), 3, not_before)

    def test_cleanup_max_date_minimum_one_day(self):
        not_before = timezone.now()
        self.assertDaysAgo(get_cleanup_max_date(-5), 1, not_before)

    # results

    def test_cleanup_reports_every_table(self):
        create_ms()
        results, duration = self.cleanup()
        self.assertIn("machine_snapshot_commit", results)
        self.assertIn("inventory_osxappinstance", results)
        self.assertEqual(len(results), 24)
        self.assertTrue(all(r["status"] == 0 for r in results.values()))
        self.assertTrue(all(r["attempts"] == 1 for r in results.values()))
        self.assertTrue(all(r["rowcount"] >= 0 for r in results.values()))
        self.assertTrue(all(r["duration"] >= 0 for r in results.values()))
        self.assertTrue(duration >= 0)

    # machine snapshot commits

    def test_cleanup_keeps_the_last_commit_of_a_machine(self):
        create_ms()
        commit = MachineSnapshotCommit.objects.get()
        MachineSnapshotCommit.objects.filter(pk=commit.pk).update(created_at=timezone.now() - timedelta(days=365))
        results, _ = self.cleanup()
        self.assertEqual(results["machine_snapshot_commit"]["rowcount"], 0)
        self.assertTrue(MachineSnapshotCommit.objects.filter(pk=commit.pk).exists())

    def test_cleanup_deletes_the_older_commits_in_batches(self):
        create_ms()
        older_commit_pks, last_commit_pk = self.force_machine_snapshot_commits(5, days=365)
        results, _ = self.cleanup(batch_size=2)
        self.assertEqual(results["machine_snapshot_commit"]["rowcount"], 5)
        self.assertEqual(MachineSnapshotCommit.objects.filter(pk__in=older_commit_pks).count(), 0)
        last_commit = MachineSnapshotCommit.objects.get()
        self.assertEqual(last_commit.pk, last_commit_pk)
        self.assertIsNone(last_commit.parent_id)

    def test_cleanup_deletes_the_newest_commits_first(self):
        create_ms()
        older_commit_pks, _ = self.force_machine_snapshot_commits(5, days=365)
        with CleanupCursor() as cursor:
            results, _ = self.cleanup(batch_size=2, cursor=cursor)
        self.assertEqual(results["machine_snapshot_commit"]["rowcount"], 5)
        # the rows of a batch are not deleted in any particular order, but each batch
        # takes the highest ids left
        newest_first = sorted(older_commit_pks, reverse=True)
        self.assertEqual([sorted(batch, reverse=True) for batch in cursor.batches],
                         [newest_first[:2], newest_first[2:4], newest_first[4:]])

    def test_cleanup_keeps_the_recent_commits(self):
        create_ms()
        self.force_machine_snapshot_commits(3, days=0)
        results, _ = self.cleanup(batch_size=2)
        self.assertEqual(results["machine_snapshot_commit"]["rowcount"], 0)
        self.assertEqual(MachineSnapshotCommit.objects.count(), 4)

    # orphans

    def test_cleanup_deletes_the_orphans_in_batches(self):
        create_ms()
        pks = self.force_orphan_osx_app_instances(5)
        results, _ = self.cleanup(batch_size=2)
        self.assertEqual(results["inventory_osxappinstance"]["rowcount"], 5)
        self.assertEqual(OSXAppInstance.objects.filter(pk__in=pks).count(), 0)

    def test_cleanup_keeps_the_linked_objects(self):
        create_ms()
        linked_pks = list(OSXAppInstance.objects.values_list("pk", flat=True))
        self.assertTrue(len(linked_pks) > 0)
        results, _ = self.cleanup(batch_size=1)
        self.assertEqual(results["inventory_osxappinstance"]["rowcount"], 0)
        self.assertEqual(OSXAppInstance.objects.filter(pk__in=linked_pks).count(), len(linked_pks))

    def test_cleanup_deletes_the_archived_machine_snapshots(self):
        create_ms()
        machine_snapshot_pk = MachineSnapshot.objects.get().pk
        MachineSnapshotCommit.objects.all().delete()
        results, _ = self.cleanup(batch_size=1)
        self.assertEqual(results["inventory_machinesnapshot"]["rowcount"], 1)
        self.assertEqual(MachineSnapshot.objects.filter(pk=machine_snapshot_pk).count(), 0)

    # integrity errors

    def test_cleanup_retries_a_batch_after_an_integrity_error(self):
        create_ms()
        self.force_orphan_osx_app_instances(1)
        with patch("zentral.contrib.inventory.utils.cleanup.time.sleep") as sleep:
            with CleanupCursor("inventory_osxappinstance", 1) as cursor:
                results, _ = self.cleanup(cursor=cursor)
        sleep.assert_called_once_with(1)
        self.assertEqual(results["inventory_osxappinstance"]["attempts"], 2)
        self.assertEqual(results["inventory_osxappinstance"]["status"], 0)
        self.assertEqual(results["inventory_osxappinstance"]["rowcount"], 1)

    def test_cleanup_gives_up_on_a_batch_after_max_attempts(self):
        create_ms()
        self.force_orphan_osx_app_instances(1)
        with patch("zentral.contrib.inventory.utils.cleanup.time.sleep"):
            with CleanupCursor("inventory_osxappinstance", MAX_ATTEMPTS) as cursor:
                results, _ = self.cleanup(cursor=cursor)
        self.assertEqual(results["inventory_osxappinstance"]["attempts"], MAX_ATTEMPTS)
        self.assertEqual(results["inventory_osxappinstance"]["status"], 1)
        self.assertEqual(results["inventory_osxappinstance"]["rowcount"], 0)
        # the tables after the failed one are still cleaned up
        self.assertEqual(results["inventory_payload"]["status"], 0)

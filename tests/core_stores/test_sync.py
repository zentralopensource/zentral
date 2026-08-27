from datetime import timedelta
from unittest.mock import Mock, patch
from django.test import TestCase
from zentral.core.stores.models import Store
from zentral.core.stores.sync import signal_store_change, StoreWorkerConfigWatcher
from .utils import force_store


class TestSignalStoreChange(TestCase):
    def test_signal_store_change(self):
        store = force_store()
        with patch("zentral.core.stores.sync.notifier") as notifier:
            signal_store_change(store)
        notifier.send_notification.assert_called_once_with("stores.store", str(store.pk))


class TestStoreWorkerConfigWatcher(TestCase):
    maxDiff = None

    def test_an_unchanged_store_is_not_a_change(self):
        store = force_store()
        watcher = StoreWorkerConfigWatcher(store, Mock())
        self.assertFalse(watcher.store_changed())

    def test_a_saved_store_is_a_change(self):
        store = force_store()
        watcher = StoreWorkerConfigWatcher(store, Mock())
        store.instance.save()  # auto_now moves updated_at
        self.assertTrue(watcher.store_changed())

    def test_a_deleted_store_is_a_change(self):
        store = force_store()
        watcher = StoreWorkerConfigWatcher(store, Mock())
        Store.objects.filter(pk=store.pk).delete()
        # the notification cannot tell a deletion apart, so this has to agree
        self.assertTrue(watcher.store_changed())

    def test_a_database_error_is_not_a_change(self):
        store = force_store()
        watcher = StoreWorkerConfigWatcher(store, Mock())
        with patch("zentral.core.stores.models.Store.objects") as objects:
            objects.filter.side_effect = Exception("boom")
            with self.assertLogs("zentral.core.stores.sync", level="ERROR") as cm:
                self.assertFalse(watcher.store_changed())
                self.assertFalse(watcher.store_changed())
        # not a reason to stop the worker, but the count shows how long it lasts
        self.assertEqual(watcher.failures, 2)
        self.assertIn(f"store worker {store.name} - could not read the store, 2 consecutive failure(s)",
                      "\n".join(cm.output))

    def test_a_read_that_works_resets_the_failures(self):
        store = force_store()
        watcher = StoreWorkerConfigWatcher(store, Mock())
        watcher.failures = 7
        self.assertFalse(watcher.store_changed())
        self.assertEqual(watcher.failures, 0)

    def test_one_read_uses_one_query(self):
        store = force_store()
        watcher = StoreWorkerConfigWatcher(store, Mock())
        with self.assertNumQueries(1):
            watcher.store_changed()

    # the notification

    def test_notification_for_this_store(self):
        store = force_store()
        stop = Mock()
        watcher = StoreWorkerConfigWatcher(store, stop)
        with self.assertLogs("zentral.core.stores.sync", level="WARNING") as cm:
            watcher.handle_notification(str(store.pk))
        stop.assert_called_once_with()
        self.assertIn(f"store worker {store.name} - store changed, found by notification", "\n".join(cm.output))

    def test_notification_for_another_store(self):
        store = force_store()
        other_store = force_store()
        stop = Mock()
        watcher = StoreWorkerConfigWatcher(store, stop)
        watcher.handle_notification(str(other_store.pk))
        stop.assert_not_called()

    def test_notification_error(self):
        store = force_store()
        stop = Mock()
        watcher = StoreWorkerConfigWatcher(store, stop)
        with self.assertLogs("zentral.core.stores.sync", level="ERROR") as cm:
            watcher.handle_notification()  # no argument
        stop.assert_not_called()
        self.assertIn(f"store worker {store.name} - could not process the store update notification",
                      "\n".join(cm.output))

    def test_start_registers_the_notifier_callback(self):
        store = force_store()
        watcher = StoreWorkerConfigWatcher(store, Mock())
        with patch("zentral.core.stores.sync.notifier") as notifier, \
             patch("zentral.core.stores.sync.threading.Thread"):
            watcher.start()
        notifier.add_callback.assert_called_once()
        self.assertEqual(notifier.add_callback.call_args.args[0], "stores.store")

    def test_context_manager_starts_and_stops(self):
        store = force_store()
        watcher = StoreWorkerConfigWatcher(store, Mock())
        with patch.object(watcher, "start") as start, patch.object(watcher, "stop") as stop:
            with watcher as entered:
                self.assertIs(entered, watcher)
                start.assert_called_once_with()
                stop.assert_not_called()
            stop.assert_called_once_with()

    # the loop

    def test_the_loop_stops_the_worker_on_an_update(self):
        store = force_store()
        stop = Mock()
        watcher = StoreWorkerConfigWatcher(store, stop)
        watcher.interval_seconds = 0
        with patch("zentral.core.stores.sync.connection") as connection:
            with patch.object(watcher, "store_changed", side_effect=[False, True]):
                with self.assertLogs("zentral.core.stores.sync", level="WARNING") as cm:
                    watcher._run()
        stop.assert_called_once_with()
        self.assertIn(f"store worker {store.name} - store changed, found by interval", "\n".join(cm.output))
        # the connection is released after every read, not held between them
        self.assertEqual(connection.close.call_count, 2)

    def test_a_failed_iteration_releases_the_connection_and_keeps_the_loop(self):
        store = force_store()
        stop = Mock()
        watcher = StoreWorkerConfigWatcher(store, stop)
        watcher.interval_seconds = 0
        calls = []

        def boom():
            calls.append(1)
            if len(calls) == 2:
                # a second iteration is what proves the first one did not kill the thread
                watcher.stop()
            raise Exception("boom")

        with patch("zentral.core.stores.sync.connection") as connection:
            with patch.object(watcher, "store_changed", side_effect=boom):
                with self.assertLogs("zentral.core.stores.sync", level="ERROR") as cm:
                    watcher._run()
        self.assertEqual(len(calls), 2)
        self.assertEqual(connection.close.call_count, 2)
        stop.assert_not_called()
        self.assertIn(f"store worker {store.name} - the store verification failed", "\n".join(cm.output))

    def test_a_stop_that_raises_leaves_the_interval_armed(self):
        store = force_store()
        stop = Mock(side_effect=[Exception("boom"), None])
        watcher = StoreWorkerConfigWatcher(store, stop)
        watcher.interval_seconds = 0
        with patch("zentral.core.stores.sync.connection"):
            with patch.object(watcher, "store_changed", return_value=True):
                with self.assertLogs("zentral.core.stores.sync", level="WARNING"):
                    watcher._run()
        # the first stop raised, so the flag stayed clear and the next interval tried it again
        self.assertEqual(stop.call_count, 2)
        self.assertTrue(watcher._stopped.is_set())

    def test_a_change_ends_the_loop(self):
        store = force_store()
        watcher = StoreWorkerConfigWatcher(store, Mock())
        # a notification stops the thread too, it has nothing left to watch
        watcher.handle_notification(str(store.pk))
        watcher.interval_seconds = 0
        with patch.object(watcher, "store_changed") as store_changed:
            watcher._run()
        store_changed.assert_not_called()

    def test_the_loop_leaves_when_it_is_stopped(self):
        store = force_store()
        stop = Mock()
        watcher = StoreWorkerConfigWatcher(store, stop)
        watcher.interval_seconds = 0
        watcher.stop()
        watcher._run()
        stop.assert_not_called()

    def test_start_runs_the_loop_in_a_thread(self):
        store = force_store()
        stop = Mock()
        watcher = StoreWorkerConfigWatcher(store, stop)
        watcher.interval_seconds = 0
        store.instance.updated_at -= timedelta(seconds=1)
        watcher.updated_at = store.instance.updated_at
        with patch("zentral.core.stores.sync.notifier"), \
             patch("zentral.core.stores.sync.threading.Thread") as thread:
            watcher.start()
        thread.assert_called_once()
        self.assertTrue(thread.call_args.kwargs["daemon"])
        self.assertEqual(thread.call_args.kwargs["target"], watcher._run)
        thread.return_value.start.assert_called_once()

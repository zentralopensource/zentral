import time
from unittest.mock import Mock, patch
from django.test import TestCase
from zentral.conf.config import ConfigDict
from zentral.core.stores.conf import Stores
from .utils import force_store


class TestStoreConf(TestCase):

    # max_custom_store_count

    @patch("zentral.core.stores.conf.settings")
    def test_default_max_custom_store_count(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.core.stores": {},
        })
        stores = Stores(with_sync=False)
        self.assertEqual(stores.max_custom_store_count, 3)

    @patch("zentral.core.stores.conf.settings")
    def test_custom_max_custom_store_count(self, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.core.stores": {"max_custom_store_count": 17},
        })
        stores = Stores(with_sync=False)
        self.assertEqual(stores.max_custom_store_count, 17)

    @patch("zentral.core.stores.conf.settings")
    @patch("zentral.core.stores.conf.logger.error")
    def test_custom_max_custom_store_count_error(self, logger_error, settings):
        settings.__getitem__.return_value = ConfigDict({
            "zentral.core.stores": {"max_custom_store_count": "not an integer"},
        })
        stores = Stores(with_sync=False)
        self.assertEqual(stores.max_custom_store_count, 3)
        logger_error.assert_called_once_with("max_custom_store_count must be an integer")

    # _start_sync

    def test_start_sync_registers_the_callback_once(self):
        stores = Stores(with_sync=True)
        with patch("zentral.core.stores.conf.notifier") as notifier:
            stores._start_sync()
            stores._start_sync()
            notifier.add_callback.assert_called_once()
        self.assertTrue(stores._sync_started)

    def test_no_sync_registers_nothing(self):
        stores = Stores(with_sync=False)
        with patch("zentral.core.stores.conf.notifier") as notifier:
            stores._start_sync()
            notifier.add_callback.assert_not_called()
        self.assertFalse(stores._sync_started)

    # _load, admin console store resolution

    def test_multiple_admin_console_stores(self):
        force_store(admin_console=True)
        force_store(admin_console=True)
        stores = Stores(with_sync=False)
        with self.assertLogs("zentral.core.stores.conf", level="ERROR") as cm:
            stores._load()
        self.assertIn("ERROR:zentral.core.stores.conf:Multiple admin console store", cm.output)
        self.assertEqual(len(list(stores)), 2)

    def test_no_admin_console_store_falls_back_to_the_first_one(self):
        force_store()
        force_store()
        stores = Stores(with_sync=False)
        with self.assertLogs("zentral.core.stores.conf", level="ERROR") as cm:
            stores._load()
        self.assertIn("ERROR:zentral.core.stores.conf:No admin console store", cm.output)
        self.assertEqual(stores.admin_console_store.instance.pk, list(stores)[0].instance.pk)

    def test_no_store_at_all(self):
        stores = Stores(with_sync=False)
        with self.assertLogs("zentral.core.stores.conf", level="ERROR") as cm:
            stores._load()
        self.assertIn("ERROR:zentral.core.stores.conf:No stores", cm.output)
        self.assertIsNone(stores.admin_console_store)

    # iter_events_url_store_for_user

    def _stores_with(self, *store_list):
        stores = Stores(with_sync=False)
        stores._stores = list(store_list)
        stores._last_load_ts = time.monotonic()
        return stores

    def test_iter_events_url_store_skips_store_without_the_url(self):
        store = force_store(admin_console=True)
        stores = self._stores_with(store)
        user = Mock(is_superuser=True, group_pk_set=set())
        # the HTTP backend does not implement machine_events_url
        self.assertEqual(list(stores.iter_events_url_store_for_user("machine", user)), [])

    def test_iter_events_url_store_for_superuser(self):
        store = force_store(admin_console=True)
        store.machine_events_url = True
        stores = self._stores_with(store)
        user = Mock(is_superuser=True, group_pk_set=set())
        self.assertEqual(list(stores.iter_events_url_store_for_user("machine", user)), [store])

    def test_iter_events_url_store_user_without_group(self):
        store = force_store(admin_console=True)
        store.machine_events_url = True
        store.events_url_authorized_role_pk_set = {1}
        stores = self._stores_with(store)
        user = Mock(is_superuser=False, group_pk_set=set())
        self.assertEqual(list(stores.iter_events_url_store_for_user("machine", user)), [])

    def test_iter_events_url_store_user_without_common_group(self):
        store = force_store(admin_console=True)
        store.machine_events_url = True
        store.events_url_authorized_role_pk_set = {1}
        stores = self._stores_with(store)
        user = Mock(is_superuser=False, group_pk_set={2})
        self.assertEqual(list(stores.iter_events_url_store_for_user("machine", user)), [])

    def test_iter_events_url_store_user_with_common_group(self):
        store = force_store(admin_console=True)
        store.machine_events_url = True
        store.events_url_authorized_role_pk_set = {1}
        stores = self._stores_with(store)
        user = Mock(is_superuser=False, group_pk_set={1, 2})
        self.assertEqual(list(stores.iter_events_url_store_for_user("machine", user)), [store])

    # iter_queue_worker_stores

    def test_iter_queue_worker_stores_skips_read_only(self):
        writable = force_store(admin_console=True)
        read_only = force_store()
        read_only.read_only = True
        stores = self._stores_with(writable, read_only)
        self.assertEqual(list(stores.iter_queue_worker_stores()), [writable])

    # max age fallback

    def test_cache_is_fresh_after_load(self):
        stores = Stores(with_sync=False)
        stores._load()
        self.assertTrue(stores._cache_is_fresh())

    def test_cache_expires(self):
        stores = Stores(with_sync=False)
        stores._load()
        stores._last_load_ts -= stores.max_age_seconds + 1
        self.assertFalse(stores._cache_is_fresh())

    def test_expired_cache_is_reloaded(self):
        stores = Stores(with_sync=False)
        stores._load()
        stores._last_load_ts -= stores.max_age_seconds + 1
        expired_ts = stores._last_load_ts
        stores._load()
        self.assertTrue(stores._cache_is_fresh())
        self.assertGreater(stores._last_load_ts, expired_ts)

    def test_forced_load_reloads_a_fresh_cache(self):
        stores = Stores(with_sync=False)
        stores._load()
        fresh_ts = stores._last_load_ts
        stores._load(force=True)
        self.assertGreater(stores._last_load_ts, fresh_ts)

    def test_clear_resets_the_load_timestamp(self):
        stores = Stores(with_sync=False)
        stores._load()
        stores.clear()
        self.assertIsNone(stores._last_load_ts)
        self.assertFalse(stores._cache_is_fresh())

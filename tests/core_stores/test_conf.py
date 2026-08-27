from unittest.mock import patch
from django.test import TestCase
from zentral.conf.config import ConfigDict
from zentral.core.stores.conf import Stores


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

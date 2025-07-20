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

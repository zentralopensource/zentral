from django.test import TestCase

from tests.mdm.utils import force_asset


class MDMAssetModelTestCase(TestCase):

    def test_asset_store_url(self):
        asset = force_asset()
        asset.metadata = {"url": "https://www.example.com"}
        asset.save()
        url = asset.store_url
        self.assertEqual(url, "https://www.example.com")

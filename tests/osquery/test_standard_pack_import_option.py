from django.test import SimpleTestCase
from django.urls import Resolver404

from tests.zentral_test_utils.app_option import load_urlconf, resolve_in
from zentral.contrib.osquery import api_views, views


APP_NAME = "zentral.contrib.osquery"
OPTION = "enable_standard_pack_import"


class StandardPackImportOptionTestCase(SimpleTestCase):

    def assertNotMounted(self, module_name, path):
        for value in ({}, {"value": False}, {"value": "true"}):
            urlconf = load_urlconf(module_name, APP_NAME, OPTION, **value)
            with self.assertRaises(Resolver404, msg=value):
                resolve_in(urlconf, path)

    def test_api_pack_slug_not_mounted(self):
        self.assertNotMounted("zentral.contrib.osquery.api_urls", "/packs/my-pack/")

    def test_api_pack_slug_mounted(self):
        urlconf = load_urlconf("zentral.contrib.osquery.api_urls", APP_NAME, OPTION, True)
        self.assertEqual(resolve_in(urlconf, "/packs/my-pack/").func.view_class, api_views.PackView)

    def test_api_pack_pk_always_mounted(self):
        urlconf = load_urlconf("zentral.contrib.osquery.api_urls", APP_NAME, OPTION)
        self.assertEqual(resolve_in(urlconf, "/packs/1/").func.view_class, api_views.PackDetail)

    def test_upload_pack_not_mounted(self):
        self.assertNotMounted("zentral.contrib.osquery.urls", "/packs/1/upload/")

    def test_upload_pack_mounted(self):
        urlconf = load_urlconf("zentral.contrib.osquery.urls", APP_NAME, OPTION, True)
        self.assertEqual(resolve_in(urlconf, "/packs/1/upload/").func.view_class, views.UploadPackView)

from django.test import SimpleTestCase
from django.urls import Resolver404

from tests.zentral_test_utils.app_option import load_urlconf, resolve_in
from zentral.contrib.santa.api_views import RuleSetUpdate


APP_NAME = "zentral.contrib.santa"
OPTION = "enable_ruleset_update_api"


class RuleSetUpdateAPIOptionTestCase(SimpleTestCase):

    def test_ruleset_update_not_mounted(self):
        for value in ({}, {"value": False}, {"value": "true"}):
            urlconf = load_urlconf("zentral.contrib.santa.api_urls", APP_NAME, OPTION, **value)
            with self.assertRaises(Resolver404, msg=value):
                resolve_in(urlconf, "/rulesets/update/")

    def test_ruleset_update_mounted(self):
        urlconf = load_urlconf("zentral.contrib.santa.api_urls", APP_NAME, OPTION, True)
        self.assertEqual(resolve_in(urlconf, "/rulesets/update/").func.view_class, RuleSetUpdate)

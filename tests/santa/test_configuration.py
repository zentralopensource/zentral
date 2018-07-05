from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.santa.models import Configuration


class SantaAPIViewsTestCase(TestCase):
    def test_local_configuration_url_keys(self):
        more_info_url = "https://{}.de".format(get_random_string(34))
        config = Configuration.objects.create(name=get_random_string(256),
                                              more_info_url=more_info_url)
        local_config = config.get_local_config()
        self.assertEqual(local_config["MoreInfoURL"], more_info_url)

    def test_blacklist_regex_default_whitelist_regex(self):
        blacklist_regex = get_random_string(34)
        config = Configuration.objects.create(name=get_random_string(256),
                                              blacklist_regex=blacklist_regex)
        local_config = config.get_local_config()
        self.assertEqual(local_config["BlacklistRegex"], blacklist_regex)
        self.assertTrue("WhitelistRegex" not in local_config)
        sync_server_config = config.get_sync_server_config()
        self.assertEqual(sync_server_config["blacklist_regex"], blacklist_regex)
        self.assertTrue(sync_server_config["whitelist_regex"].startswith("NON_MATCHING_PLACEHOLDER_"))

    def test_whitelist_regex_default_blacklist_regex(self):
        whitelist_regex = get_random_string(34)
        config = Configuration.objects.create(name=get_random_string(256),
                                              whitelist_regex=whitelist_regex)
        local_config = config.get_local_config()
        self.assertEqual(local_config["WhitelistRegex"], whitelist_regex)
        self.assertTrue("BlacklistRegex" not in local_config)
        sync_server_config = config.get_sync_server_config()
        self.assertEqual(sync_server_config["whitelist_regex"], whitelist_regex)
        self.assertTrue(sync_server_config["blacklist_regex"].startswith("NON_MATCHING_PLACEHOLDER_"))

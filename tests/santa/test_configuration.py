from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.santa.models import Configuration


class SantaConfigurationTestCase(TestCase):
    def test_local_configuration_url_keys(self):
        config = Configuration.objects.create(name=get_random_string(256))
        local_config = config.get_local_config()
        self.assertEqual(local_config["ClientMode"], config.client_mode)

    def test_blocked_path_regex_default_allowed_path_regex(self):
        blocked_path_regex = get_random_string(34)
        config = Configuration.objects.create(name=get_random_string(256),
                                              blocked_path_regex=blocked_path_regex)
        local_config = config.get_local_config()
        self.assertEqual(local_config["BlockedPathRegex"], blocked_path_regex)
        self.assertTrue("AllowedPathRegex" not in local_config)
        sync_server_config = config.get_sync_server_config(get_random_string(12), (1, 14))
        self.assertEqual(sync_server_config["blocked_path_regex"], blocked_path_regex)
        self.assertTrue(sync_server_config["allowed_path_regex"].startswith("NON_MATCHING_PLACEHOLDER_"))

    def test_allowed_path_regex_default_blocked_path_regex(self):
        allowed_path_regex = get_random_string(34)
        config = Configuration.objects.create(name=get_random_string(256),
                                              allowed_path_regex=allowed_path_regex)
        local_config = config.get_local_config()
        self.assertEqual(local_config["AllowedPathRegex"], allowed_path_regex)
        self.assertTrue("BlockedPathRegex" not in local_config)
        sync_server_config = config.get_sync_server_config(get_random_string(12), (1, 14))
        self.assertEqual(sync_server_config["allowed_path_regex"], allowed_path_regex)
        self.assertTrue(sync_server_config["blocked_path_regex"].startswith("NON_MATCHING_PLACEHOLDER_"))

    def test_enable_all_event_upload_local_config(self):
        config = Configuration.objects.create(name=get_random_string(256))
        self.assertNotIn("EnableAllEventUpload", config.get_local_config())
        config.enable_all_event_upload_shard = 100
        config.save()
        self.assertNotIn("EnableAllEventUpload", config.get_local_config())

    def test_enable_all_event_upload_sync_server_config_0(self):
        config = Configuration.objects.create(pk=1000000000,
                                              name=get_random_string(256),
                                              enable_all_event_upload_shard=0)
        self.assertEqual(config.get_sync_server_config("111111", (2022, 1))["enable_all_event_upload"], False)
        self.assertEqual(config.get_sync_server_config("777777", (2022, 1))["enable_all_event_upload"], False)

    def test_enable_all_event_upload_sync_server_config_50(self):
        config = Configuration.objects.create(pk=1000000000,
                                              name=get_random_string(256),
                                              enable_all_event_upload_shard=50)
        self.assertEqual(config.get_sync_server_config("111111", (2022, 1))["enable_all_event_upload"], True)
        self.assertEqual(config.get_sync_server_config("777777", (2022, 1))["enable_all_event_upload"], False)

    def test_enable_all_event_upload_sync_server_config_100(self):
        config = Configuration.objects.create(pk=1000000000,
                                              name=get_random_string(256),
                                              enable_all_event_upload_shard=100)
        self.assertEqual(config.get_sync_server_config("111111", (2022, 1))["enable_all_event_upload"], True)
        self.assertEqual(config.get_sync_server_config("777777", (2022, 1))["enable_all_event_upload"], True)

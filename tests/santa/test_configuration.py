import re
from importlib import import_module
from unittest.mock import patch
from django.apps import apps
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.santa.models import Configuration, voting_portal_event_detail_url
from zentral.core.incidents.models import Severity
from .utils import force_realm


class SantaConfigurationTestCase(TestCase):
    # get_sync_incident_severity

    def test_get_sync_incident_severity(self):
        config = Configuration.objects.create(name=get_random_string(256),
                                              sync_incident_severity=Severity.MAJOR.value)
        self.assertEqual(config.get_sync_incident_severity(), Severity.MAJOR)

    def test_get_unknown_sync_incident_severity_none(self):
        config = Configuration.objects.create(name=get_random_string(256))
        Configuration.objects.filter(pk=config.pk).update(sync_incident_severity=42)
        config.refresh_from_db()
        with self.assertLogs("zentral.contrib.santa.models", level="ERROR") as cm:
            self.assertEqual(config.get_sync_incident_severity(), Severity.NONE)
        self.assertEqual(
            cm.output,
            [f"ERROR:zentral.contrib.santa.models:Configuration {config.pk}: unknown sync incident severity 42"]
        )

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
        self.assertEqual(sync_server_config["allowed_path_regex"], Configuration.NON_MATCHING_PATH_REGEX)

    def test_allowed_path_regex_default_blocked_path_regex(self):
        allowed_path_regex = get_random_string(34)
        config = Configuration.objects.create(name=get_random_string(256),
                                              allowed_path_regex=allowed_path_regex)
        local_config = config.get_local_config()
        self.assertEqual(local_config["AllowedPathRegex"], allowed_path_regex)
        self.assertTrue("BlockedPathRegex" not in local_config)
        sync_server_config = config.get_sync_server_config(get_random_string(12), (1, 14))
        self.assertEqual(sync_server_config["allowed_path_regex"], allowed_path_regex)
        self.assertEqual(sync_server_config["blocked_path_regex"], Configuration.NON_MATCHING_PATH_REGEX)

    def test_non_matching_path_regex_stable_across_preflights(self):
        # a value that changed on every preflight made the client flush all its decision
        # caches twice per full sync
        config = Configuration.objects.create(name=get_random_string(256))
        serial_number = get_random_string(12)
        first = config.get_sync_server_config(serial_number, (1, 14))
        second = config.get_sync_server_config(serial_number, (1, 14))
        for attr in ("allowed_path_regex", "blocked_path_regex"):
            self.assertEqual(first[attr], Configuration.NON_MATCHING_PATH_REGEX)
            self.assertEqual(first[attr], second[attr])

    def test_non_matching_path_regex_matches_no_path(self):
        # the client compiles the pattern with ICU, re only guards against the constant being
        # replaced by something a path could match
        for path in ("/", "/usr/local/bin/santactl", Configuration.NON_MATCHING_PATH_REGEX, ""):
            self.assertIsNone(re.search(Configuration.NON_MATCHING_PATH_REGEX, path))

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

    # event detail

    def test_event_detail_local_source_distributes_nothing(self):
        config = Configuration.objects.create(name=get_random_string(256),
                                              event_detail_url="https://www.example.com/blocked/",
                                              event_detail_text="More info")
        self.assertEqual(config.get_event_detail(), (None, None))
        self.assertNotIn("EventDetailURL", config.get_local_config())
        self.assertNotIn("EventDetailText", config.get_local_config())
        sync_server_config = config.get_sync_server_config(get_random_string(12), (2022, 1))
        self.assertNotIn("event_detail_url", sync_server_config)
        self.assertNotIn("event_detail_text", sync_server_config)

    def test_event_detail_none_source_removes_the_button(self):
        config = Configuration.objects.create(name=get_random_string(256),
                                              event_detail_source=Configuration.EventDetailSource.NONE)
        self.assertEqual(config.get_event_detail(), (Configuration.NO_EVENT_DETAIL_URL, None))
        local_config = config.get_local_config()
        self.assertEqual(local_config["EventDetailURL"], "null")
        self.assertNotIn("EventDetailText", local_config)
        sync_server_config = config.get_sync_server_config(get_random_string(12), (2022, 1))
        self.assertEqual(sync_server_config["event_detail_url"], "null")
        self.assertNotIn("event_detail_text", sync_server_config)

    def test_event_detail_custom_source(self):
        url = "https://www.example.com/blocked/?fid=%file_identifier%"
        config = Configuration.objects.create(name=get_random_string(256),
                                              event_detail_source=Configuration.EventDetailSource.CUSTOM,
                                              event_detail_url=url,
                                              event_detail_text="Request an exception")
        self.assertEqual(config.get_event_detail(), (url, "Request an exception"))
        local_config = config.get_local_config()
        self.assertEqual(local_config["EventDetailURL"], url)
        self.assertEqual(local_config["EventDetailText"], "Request an exception")
        sync_server_config = config.get_sync_server_config(get_random_string(12), (2022, 1))
        self.assertEqual(sync_server_config["event_detail_url"], url)
        self.assertEqual(sync_server_config["event_detail_text"], "Request an exception")

    def test_event_detail_voting_portal_source(self):
        realm = force_realm(user_portal=True)
        config = Configuration.objects.create(name=get_random_string(256),
                                              voting_realm=realm,
                                              event_detail_source=Configuration.EventDetailSource.VOTING_PORTAL)
        url, text = config.get_event_detail()
        self.assertEqual(
            url,
            f"https://zentral/public/realms/{realm.pk}/up/santa/event_detail/"
            "?bofid=%bundle_or_file_identifier%&fid=%file_identifier%&mid=%machine_id%"
            "&tid=%team_id%&sid=%signing_id%&cdh=%cdhash%"
        )
        self.assertEqual(text, Configuration.DEFAULT_EVENT_DETAIL_TEXT)
        sync_server_config = config.get_sync_server_config(get_random_string(12), (2022, 1))
        self.assertEqual(sync_server_config["event_detail_url"], url)
        self.assertEqual(sync_server_config["event_detail_text"], "More info")

    def test_event_detail_voting_portal_source_custom_text(self):
        realm = force_realm(user_portal=True)
        config = Configuration.objects.create(name=get_random_string(256),
                                              voting_realm=realm,
                                              event_detail_source=Configuration.EventDetailSource.VOTING_PORTAL,
                                              event_detail_text="Request an exception")
        _, text = config.get_event_detail()
        self.assertEqual(text, "Request an exception")

    def test_event_detail_voting_portal_source_unavailable_distributes_nothing(self):
        config = Configuration.objects.create(name=get_random_string(256),
                                              event_detail_source=Configuration.EventDetailSource.VOTING_PORTAL)
        with self.assertLogs("zentral.contrib.santa.models", level="ERROR") as cm:
            self.assertEqual(config.get_event_detail(), (None, None))
        self.assertEqual(
            cm.output,
            [f"ERROR:zentral.contrib.santa.models:Configuration {config.pk}: "
             "voting portal event detail URL unavailable"]
        )

    def test_event_detail_button_local_source(self):
        config = Configuration.objects.create(name=get_random_string(256))
        self.assertEqual(config.get_event_detail_button(), (None, None))

    def test_event_detail_button_none_source(self):
        config = Configuration.objects.create(name=get_random_string(256),
                                              event_detail_source=Configuration.EventDetailSource.NONE)
        self.assertEqual(config.get_event_detail_button(), (None, None))

    def test_event_detail_button_custom_source(self):
        url = "https://www.example.com/blocked/"
        config = Configuration.objects.create(name=get_random_string(256),
                                              event_detail_source=Configuration.EventDetailSource.CUSTOM,
                                              event_detail_url=url,
                                              event_detail_text="Request an exception")
        self.assertEqual(config.get_event_detail_button(), (url, "Request an exception"))

    def test_event_detail_button_voting_portal_source(self):
        config = Configuration.objects.create(name=get_random_string(256),
                                              voting_realm=force_realm(user_portal=True),
                                              event_detail_source=Configuration.EventDetailSource.VOTING_PORTAL)
        url, text = config.get_event_detail_button()
        self.assertIn("/up/santa/event_detail/", url)
        self.assertEqual(text, Configuration.DEFAULT_EVENT_DETAIL_TEXT)

    def test_event_detail_voting_portal_source_without_the_app_setting(self):
        config = Configuration.objects.create(name=get_random_string(256),
                                              voting_realm=force_realm(user_portal=True),
                                              event_detail_source=Configuration.EventDetailSource.VOTING_PORTAL)
        with patch("zentral.contrib.santa.models.settings", {"apps": {"zentral.contrib.santa": {}}}):
            self.assertIsNone(voting_portal_event_detail_url(config.voting_realm))
            with self.assertLogs("zentral.contrib.santa.models", level="ERROR"):
                self.assertEqual(config.get_event_detail(), (None, None))

    def test_migration_reverse_restores_the_local_source(self):
        migration = import_module("zentral.contrib.santa.migrations.0047_event_detail_source")
        config = Configuration.objects.create(name=get_random_string(256),
                                              voting_realm=force_realm(user_portal=True),
                                              event_detail_source=Configuration.EventDetailSource.VOTING_PORTAL)
        migration.unset_voting_portal_source(apps, None)
        config.refresh_from_db()
        self.assertEqual(config.event_detail_source, Configuration.EventDetailSource.LOCAL)

    def test_migration_forward_sets_the_voting_portal_source(self):
        migration = import_module("zentral.contrib.santa.migrations.0047_event_detail_source")
        with_portal = Configuration.objects.create(name=get_random_string(256),
                                                   voting_realm=force_realm(user_portal=True))
        without_portal = Configuration.objects.create(name=get_random_string(256),
                                                      voting_realm=force_realm(user_portal=False))
        no_realm = Configuration.objects.create(name=get_random_string(256))
        migration.set_voting_portal_source(apps, None)
        for config, expected in ((with_portal, Configuration.EventDetailSource.VOTING_PORTAL),
                                 (without_portal, Configuration.EventDetailSource.LOCAL),
                                 (no_realm, Configuration.EventDetailSource.LOCAL)):
            config.refresh_from_db()
            self.assertEqual(config.event_detail_source, expected)

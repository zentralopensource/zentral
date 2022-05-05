import datetime
from functools import reduce
import operator
import plistlib
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.test import TestCase, override_settings
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit, File, Tag
from accounts.models import User
from zentral.contrib.santa.models import Bundle, Configuration, Rule, Target


def get_random_sha256():
    return get_random_string(64, "abcdef0123456789")


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class SantaSetupViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        # file tree
        cls.file_sha256 = get_random_sha256()
        cls.file_name = get_random_string(12)
        cls.file_bundle_name = get_random_string(12)
        cls.file_cert_sha256 = get_random_sha256()
        cls.file_team_id = get_random_string(10, allowed_chars="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        cls.file_cert_cn = f"Developer ID Application: YOLO ({cls.file_team_id})"
        cls.file, _ = File.objects.commit({
            'source': {'module': 'zentral.contrib.santa', 'name': 'Santa events'},
            'bundle': {'bundle_id': 'servicecontroller:com.apple.stomp.transcoderx',
                       'bundle_name': cls.file_bundle_name,
                       'bundle_version': '3.5.3',
                       'bundle_version_str': '3.5.3'},
            'bundle_path': ('/Library/Frameworks/Compressor.framework/'
                            'Versions/A/Resources/CompressorTranscoderX.bundle'),
            'name': cls.file_name,
            'path': ('/Library/Frameworks/Compressor.framework/'
                     'Versions/A/Resources/CompressorTranscoderX.bundle/Contents/MacOS'),
            'sha_256': cls.file_sha256,
            'signed_by': {
                'common_name': cls.file_cert_cn,
                'organization': 'Apple Inc.',
                'organizational_unit': cls.file_team_id,
                'sha_256': cls.file_cert_sha256,
                'valid_from': datetime.datetime(2007, 2, 23, 22, 2, 56),
                'valid_until': datetime.datetime(2015, 1, 14, 22, 2, 56),
                'signed_by': {
                    'common_name': 'Apple Code Signing Certification Authority',
                    'organization': 'Apple Inc.',
                    'organizational_unit': 'Apple Certification Authority',
                    'sha_256': '3afa0bf5027fd0532f436b39363a680aefd6baf7bf6a4f97f17be2937b84b150',
                    'valid_from': datetime.datetime(2007, 2, 14, 21, 19, 19),
                    'valid_until': datetime.datetime(2015, 2, 14, 21, 19, 19),
                    'signed_by': {
                        'common_name': 'Apple Root CA',
                        'organization': 'Apple Inc.',
                        'organizational_unit': 'Apple Certification Authority',
                        'sha_256': 'b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024',
                        'valid_from': datetime.datetime(2006, 4, 25, 21, 40, 36),
                        'valid_until': datetime.datetime(2035, 2, 9, 21, 40, 36),
                    },
                },
             }
        })
        cls.file_target = Target.objects.create(type=Target.BINARY, identifier=cls.file_sha256)

    # utility methods

    def _login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def _login(self, *permissions):
        if permissions:
            permission_filter = reduce(operator.or_, (
                Q(content_type__app_label=app_label, codename=codename)
                for app_label, codename in (
                    permission.split(".")
                    for permission in permissions
                )
            ))
            self.group.permissions.set(list(Permission.objects.filter(permission_filter)))
        else:
            self.group.permissions.clear()
        self.client.force_login(self.user)

    def _force_configuration(self):
        return Configuration.objects.create(name=get_random_string(12), enable_sysx_cache=True)

    def _force_bundle(self):
        bundle_target = Target.objects.create(type=Target.BUNDLE, identifier=get_random_sha256())
        return Bundle.objects.create(
            target=bundle_target,
            executable_rel_path=get_random_string(12),
            bundle_id=self.file.bundle.bundle_id,
            name=self.file_bundle_name,
            version=self.file.bundle.bundle_version,
            version_str=self.file.bundle.bundle_version_str,
            binary_count=1
        )

    # index

    def test_index_redirect(self):
        self._login_redirect(reverse("santa:index"))

    def test_index_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:index"))
        self.assertEqual(response.status_code, 403)

    def test_index(self):
        configuration = self._force_configuration()

        self._login("santa.view_configuration")
        response = self.client.get(reverse("santa:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/index.html")
        # 1 configuration
        self.assertContains(response, "1 Configuration")
        self.assertContains(response, configuration.name)
        # no perms, no targets
        self.assertNotContains(response, "3 Collected targets")

        self._login("santa.view_target")
        response = self.client.get(reverse("santa:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/index.html")
        # no perms, no configuration
        self.assertNotContains(response, "1 Configuration")
        self.assertNotContains(response, configuration.name)
        # 1 binary, 1 certificate
        self.assertContains(response, "3 Collected targets")

    # configurations

    def test_configurations_redirect(self):
        self._login_redirect(reverse("santa:configuration_list"))
        self._login_redirect(reverse("santa:create_configuration"))

    def test_configuration_redirect(self):
        configuration = self._force_configuration()
        self._login_redirect(configuration.get_absolute_url())

    def test_configuration_permission_denied(self):
        configuration = self._force_configuration()
        self._login()
        response = self.client.get(configuration.get_absolute_url())
        self.assertEqual(response.status_code, 403)

    def test_configuration_without_event_links(self):
        configuration = self._force_configuration()
        self._login("santa.view_configuration")
        response = self.client.get(configuration.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_detail.html")
        self.assertNotContains(response, reverse("santa:configuration_events",
                                                 args=(configuration.pk,)))
        self.assertNotContains(response, reverse("santa:configuration_events_store_redirect",
                                                 args=(configuration.pk,)))

    def test_configuration_with_event_links(self):
        configuration = self._force_configuration()
        self._login("santa.view_configuration",
                    "santa.view_enrollment",
                    "santa.view_rule",
                    "santa.view_ruleset")
        response = self.client.get(configuration.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_detail.html")
        self.assertContains(response, reverse("santa:configuration_events",
                                              args=(configuration.pk,)))

    def test_configuration_events_redirect(self):
        configuration = self._force_configuration()
        self._login_redirect(reverse("santa:configuration_events", args=(configuration.pk,)))

    def test_configuration_events_permission_denied(self):
        configuration = self._force_configuration()
        self._login("santa.view_configuration")
        response = self.client.get(reverse("santa:configuration_events", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.get_aggregated_object_event_counts")
    def test_configuration_events_ok(self, get_aggregated_object_event_counts):
        get_aggregated_object_event_counts.return_value = {}
        configuration = self._force_configuration()
        self._login("santa.view_configuration",
                    "santa.view_enrollment",
                    "santa.view_rule",
                    "santa.view_ruleset")
        response = self.client.get(reverse("santa:configuration_events", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_events.html")

    def test_fetch_configuration_events_redirect(self):
        configuration = self._force_configuration()
        self._login_redirect(reverse("santa:fetch_configuration_events", args=(configuration.pk,)))

    def test_fetch_configuration_events_permission_denied(self):
        configuration = self._force_configuration()
        self._login("santa.view_rule")
        response = self.client.get(reverse("santa:fetch_configuration_events", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.fetch_object_events")
    def test_fetch_configuration_events_ok(self, fetch_object_events):
        fetch_object_events.return_value = ([], None)
        configuration = self._force_configuration()
        self._login("santa.view_configuration",
                    "santa.view_enrollment",
                    "santa.view_rule",
                    "santa.view_ruleset")
        response = self.client.get(reverse("santa:fetch_configuration_events", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/stores/events_events.html")

    def test_get_create_configuration_view(self):
        self._login()
        response = self.client.get(reverse("santa:create_configuration"))
        self.assertEqual(response.status_code, 403)
        self._login("santa.add_configuration")
        response = self.client.get(reverse("santa:create_configuration"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_form.html")
        self.assertContains(response, "Santa configuration")

    def test_post_create_configuration_view(self):
        self._login("santa.add_configuration", "santa.view_configuration")
        response = self.client.post(reverse("santa:create_configuration"),
                                    {"name": get_random_string(64),
                                     "batch_size": 50,
                                     "client_mode": "1",
                                     "banned_block_message": "yo",
                                     "enable_page_zero_protection": "on",
                                     "enable_sysx_cache": "on",
                                     "mode_notification_lockdown": "lockdown",
                                     "mode_notification_monitor": "monitor",
                                     "unknown_block_message": "block",
                                     "full_sync_interval": 602,
                                     "allow_unknown_shard": 87,
                                     "enable_all_event_upload_shard": 65,
                                     }, follow=True)
        configuration = response.context["object"]
        self.assertEqual(response.status_code, 200)
        self.assertEqual(configuration.enable_sysx_cache, True)
        self.assertEqual(configuration.full_sync_interval, 602)
        self.assertEqual(configuration.allow_unknown_shard, 87)
        self.assertEqual(configuration.enable_all_event_upload_shard, 65)
        self.assertTemplateUsed(response, "santa/configuration_detail.html")
        self.assertContains(response, configuration.name)

    def test_post_update_configuration_view(self):
        self._login("santa.add_configuration", "santa.view_configuration")
        configuration = self._force_configuration()
        response = self.client.post(reverse("santa:update_configuration", args=(configuration.pk,)),
                                    {"name": configuration.name,
                                     "batch_size": 50,
                                     "client_mode": "1",
                                     "banned_block_message": "yo",
                                     "enable_page_zero_protection": "on",
                                     "mode_notification_lockdown": "new lockdown message",
                                     "mode_notification_monitor": "monitor",
                                     "unknown_block_message": "block",
                                     "full_sync_interval": 603,
                                     "allow_unknown_shard": 91,
                                     "enable_all_event_upload_shard": 76,
                                     }, follow=True)
        self.assertEqual(response.status_code, 403)
        self._login("santa.add_configuration", "santa.change_configuration", "santa.view_configuration")
        response = self.client.post(reverse("santa:update_configuration", args=(configuration.pk,)),
                                    {"name": configuration.name,
                                     "batch_size": 50,
                                     "client_mode": "1",
                                     "banned_block_message": "yo",
                                     "enable_page_zero_protection": "on",
                                     "mode_notification_lockdown": "new lockdown message",
                                     "mode_notification_monitor": "monitor",
                                     "unknown_block_message": "block",
                                     "full_sync_interval": 603,
                                     "allow_unknown_shard": 91,
                                     "enable_all_event_upload_shard": 76,
                                     }, follow=True)
        configuration = response.context["object"]
        self.assertEqual(configuration.enable_sysx_cache, False)
        self.assertEqual(configuration.full_sync_interval, 603)
        self.assertEqual(configuration.allow_unknown_shard, 91)
        self.assertEqual(configuration.enable_all_event_upload_shard, 76)
        self.assertTemplateUsed(response, "santa/configuration_detail.html")
        self.assertContains(response, "new lockdown message")

    def test_get_create_enrollment_view(self):
        self._login("santa.add_configuration", "santa.view_configuration")
        configuration = self._force_configuration()
        response = self.client.get(reverse("santa:create_enrollment", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)
        self._login("santa.add_configuration", "santa.view_configuration", "santa.add_enrollment")
        response = self.client.get(reverse("santa:create_enrollment", args=(configuration.pk,)))
        self.assertTemplateUsed(response, "santa/enrollment_form.html")
        self.assertContains(response, "Create enrollment")
        self.assertContains(response, configuration.name)

    def create_enrollment(self, configuration, no_assertions=False):
        mbu = MetaBusinessUnit.objects.create(name="{} MBU".format(configuration.name))
        mbu.create_enrollment_business_unit()
        response = self.client.post(reverse("santa:create_enrollment", args=(configuration.pk,)),
                                    {"secret-meta_business_unit": mbu.pk,
                                     "configuration": configuration.pk,
                                     "santa_release": ""}, follow=True)
        if no_assertions:
            return response, None
        enrollment = response.context["enrollments"][0]
        self.assertEqual(enrollment.version, 1)
        return response, enrollment

    def test_post_create_enrollment_view(self):
        self._login("santa.add_configuration", "santa.view_configuration")
        configuration = self._force_configuration()
        response, enrollment = self.create_enrollment(configuration, no_assertions=True)
        self.assertEqual(response.status_code, 403)
        self._login("santa.add_configuration", "santa.view_configuration", "santa.add_enrollment")
        response, enrollment = self.create_enrollment(configuration)
        self.assertTemplateUsed(response, "santa/configuration_detail.html")
        self.assertEqual(response.context["object"], configuration)
        # response does not contain enrollment secret meta business unit name
        self.assertNotContains(response, enrollment.secret.meta_business_unit.name)
        # response does not contain link to download enrollment configuration plist
        self.assertNotContains(response, reverse("santa:enrollment_configuration_plist",
                                                 args=(configuration.pk, enrollment.pk)))
        # response does not contain link to download enrollment configuration profile
        self.assertNotContains(response, reverse("santa:enrollment_configuration_profile",
                                                 args=(configuration.pk, enrollment.pk)))
        self._login("santa.view_configuration", "santa.view_enrollment")
        response = self.client.get(configuration.get_absolute_url())
        # response contains enrollment secret meta business unit name
        self.assertContains(response, enrollment.secret.meta_business_unit.name)
        # response contains link to download enrollment configuration plist
        self.assertContains(response, reverse("santa:enrollment_configuration_plist",
                                              args=(configuration.pk, enrollment.pk)))
        # response contains link to download enrollment configuration profile
        self.assertContains(response, reverse("santa:enrollment_configuration_profile",
                                              args=(configuration.pk, enrollment.pk)))

    def test_enrollment_configuration_view(self):
        self._login("santa.add_configuration", "santa.view_configuration",
                    "santa.add_enrollment", "santa.view_enrollment")
        configuration = self._force_configuration()
        _, enrollment = self.create_enrollment(configuration)
        self.client.logout()
        enrollment_configuration_plist_url = reverse(
            "santa:enrollment_configuration_plist", args=(configuration.pk, enrollment.pk)
        )
        self._login_redirect(enrollment_configuration_plist_url)
        enrollment_configuration_profile_url = reverse(
            "santa:enrollment_configuration_profile", args=(configuration.pk, enrollment.pk)
        )
        self._login_redirect(enrollment_configuration_profile_url)
        self._login()
        response = self.client.get(enrollment_configuration_plist_url)
        self.assertEqual(response.status_code, 403)
        response = self.client.get(enrollment_configuration_profile_url)
        self.assertEqual(response.status_code, 403)
        self._login("santa.view_enrollment")
        response = self.client.get(enrollment_configuration_plist_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "application/x-plist")
        plist_config = plistlib.loads(response.content)
        self.assertTrue(plist_config["SyncBaseURL"].endswith(
            f"/santa/sync/{enrollment.secret.secret}/"
        ))
        self.assertEqual(plist_config["EnableSysxCache"], configuration.enable_sysx_cache)
        response = self.client.get(enrollment_configuration_profile_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "application/octet-stream")

    def test_configuration_rules_redirects(self):
        self._login("santa.add_configuration", "santa.view_configuration")
        configuration = self._force_configuration()
        self.client.logout()
        self._login_redirect(reverse("santa:configuration_rules", args=(configuration.pk,)))
        self._login_redirect(reverse("santa:create_configuration_rule", args=(configuration.pk,)))
        self._login_redirect(reverse("santa:pick_rule_binary", args=(configuration.pk,)))
        self._login_redirect(reverse("santa:pick_rule_bundle", args=(configuration.pk,)))
        self._login_redirect(reverse("santa:pick_rule_certificate", args=(configuration.pk,)))

    def test_configuration_rules_permission_denied(self):
        self._login("santa.add_configuration", "santa.view_configuration")
        configuration = self._force_configuration()
        for view_name in ("configuration_rules", "create_configuration_rule",
                          "pick_rule_binary", "pick_rule_bundle", "pick_rule_certificate"):
            response = self.client.get(reverse(f"santa:{view_name}", args=(configuration.pk,)))
            self.assertEqual(response.status_code, 403)

    def test_create_configuration_rule(self):
        self._login("santa.add_configuration", "santa.view_configuration")
        configuration = self._force_configuration()
        # create
        binary_hash = get_random_sha256()
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                    {"target_type": Target.BINARY,
                                     "target_identifier": binary_hash,
                                     "policy": Rule.ALLOWLIST}, follow=True)
        self.assertEqual(response.status_code, 403)
        self._login("santa.add_rule", "santa.view_rule")
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                    {"target_type": Target.BINARY,
                                     "target_identifier": binary_hash,
                                     "policy": Rule.ALLOWLIST}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_rules.html")
        rule = response.context["object_list"][0]
        self.assertEqual(rule.configuration, configuration)
        self.assertEqual(rule.target.identifier, binary_hash)
        self.assertEqual(rule.target.type, Target.BINARY)
        self.assertEqual(rule.policy, Rule.ALLOWLIST)
        self.assertEqual(rule.custom_msg, "")
        self.assertEqual(rule.serial_numbers, [])
        self.assertEqual(rule.primary_users, [])

    def test_create_conflict_configuration_rule(self):
        self._login("santa.add_configuration", "santa.view_configuration",
                    "santa.add_rule", "santa.view_rule")
        configuration = self._force_configuration()
        # create
        binary_hash = get_random_sha256()
        self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                         {"target_type": Target.BINARY,
                          "target_identifier": binary_hash,
                          "policy": Rule.ALLOWLIST}, follow=True)
        # conflict
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                    {"target_type": Target.BINARY,
                                     "target_identifier": binary_hash,
                                     "policy": Rule.BLOCKLIST}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/rule_form.html")
        form = response.context["form"]
        self.assertEqual(form.errors, {'__all__': ['A rule for this target already exists']})

    def test_create_configuration_rule_scope_conflict(self):
        self._login("santa.add_configuration", "santa.view_configuration",
                    "santa.add_rule", "santa.view_rule")
        configuration = self._force_configuration()
        binary_hash = get_random_sha256()
        tags = [Tag.objects.create(name=get_random_string(32)) for _ in range(3)]
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                    {"target_type": Target.BINARY,
                                     "target_identifier": binary_hash,
                                     "policy": Rule.ALLOWLIST,
                                     "serial_numbers": "12345678,23456789",
                                     "excluded_serial_numbers": "12345678",
                                     "primary_users": "yolo,fomo",
                                     "excluded_primary_users": "fomo",
                                     "tags": [t.pk for t in tags],
                                     "excluded_tags": [tags[0].pk]}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/rule_form.html")
        form = response.context["form"]
        self.assertEqual(form.errors, {'excluded_serial_numbers': ["'12345678' both included and excluded"],
                                       'excluded_primary_users': ["'fomo' both included and excluded"],
                                       'excluded_tags': [f"'{tags[0].name}' both included and excluded"]})

    def test_update_configuration_rule(self):
        self._login("santa.add_configuration", "santa.view_configuration",
                    "santa.add_rule", "santa.view_rule")
        configuration = self._force_configuration()
        # create
        binary_hash = get_random_sha256()
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                    {"target_type": Target.BINARY,
                                     "target_identifier": binary_hash,
                                     "policy": Rule.ALLOWLIST}, follow=True)
        rule = response.context["object_list"][0]
        # update
        custom_message = get_random_string(12)
        serial_numbers = [get_random_string(12) for i in range(3)]
        primary_users = [get_random_string(12) for i in range(12)]
        response = self.client.post(reverse("santa:update_configuration_rule", args=(configuration.pk, rule.pk)),
                                    {"target_type": Target.BINARY,
                                     "target_identifier": binary_hash,
                                     "policy": Rule.BLOCKLIST,
                                     "custom_msg": custom_message,
                                     "serial_numbers": ", ".join(serial_numbers),
                                     "primary_users": ",".join(primary_users)}, follow=True)
        self.assertEqual(response.status_code, 403)
        self._login("santa.change_rule", "santa.view_rule")
        response = self.client.post(reverse("santa:update_configuration_rule", args=(configuration.pk, rule.pk)),
                                    {"target_type": Target.BINARY,
                                     "target_identifier": binary_hash,
                                     "policy": Rule.BLOCKLIST,
                                     "custom_msg": custom_message,
                                     "serial_numbers": ", ".join(serial_numbers),
                                     "primary_users": ",".join(primary_users)}, follow=True)
        self.assertTemplateUsed(response, "santa/configuration_rules.html")
        rule = response.context["object_list"][0]
        self.assertEqual(rule.configuration, configuration)
        self.assertEqual(rule.target.identifier, binary_hash)
        self.assertEqual(rule.target.type, Target.BINARY)
        self.assertEqual(rule.policy, Rule.BLOCKLIST)
        self.assertEqual(rule.custom_msg, custom_message)
        self.assertEqual(rule.serial_numbers, serial_numbers)
        self.assertEqual(rule.primary_users, primary_users)

    def test_update_configuration_rule_scope_conflict(self):
        self._login("santa.add_configuration", "santa.view_configuration",
                    "santa.add_rule", "santa.view_rule", "santa.change_rule")
        configuration = self._force_configuration()
        # create
        binary_hash = get_random_sha256()
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                    {"target_type": Target.BINARY,
                                     "target_identifier": binary_hash,
                                     "policy": Rule.ALLOWLIST}, follow=True)
        rule = response.context["object_list"][0]
        # update
        tags = [Tag.objects.create(name=get_random_string(32)) for _ in range(3)]
        response = self.client.post(reverse("santa:update_configuration_rule", args=(configuration.pk, rule.pk)),
                                    {"target_type": Target.BINARY,
                                     "target_identifier": binary_hash,
                                     "policy": Rule.ALLOWLIST,
                                     "serial_numbers": "12345678,23456789",
                                     "excluded_serial_numbers": "12345678",
                                     "primary_users": "yolo,fomo",
                                     "excluded_primary_users": "fomo",
                                     "tags": [t.pk for t in tags],
                                     "excluded_tags": [tags[0].pk]}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/rule_form.html")
        form = response.context["form"]
        self.assertEqual(form.errors, {'excluded_serial_numbers': ["'12345678' both included and excluded"],
                                       'excluded_primary_users': ["'fomo' both included and excluded"],
                                       'excluded_tags': [f"'{tags[0].name}' both included and excluded"]})

    def test_delete_configuration_rule(self):
        self._login("santa.add_configuration", "santa.view_configuration",
                    "santa.add_rule", "santa.view_rule")
        configuration = self._force_configuration()
        # create
        binary_hash = get_random_sha256()
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                    {"target_type": Target.BINARY,
                                     "target_identifier": binary_hash,
                                     "policy": Rule.ALLOWLIST}, follow=True)
        rule = response.context["object_list"][0]
        # delete GET
        response = self.client.get(reverse("santa:delete_configuration_rule", args=(configuration.pk, rule.pk)))
        self.assertEqual(response.status_code, 403)
        self._login("santa.delete_rule", "santa.view_rule")
        response = self.client.get(reverse("santa:delete_configuration_rule", args=(configuration.pk, rule.pk)))
        self.assertTemplateUsed(response, "santa/rule_confirm_delete.html")
        self.assertContains(response, binary_hash)
        # delete POST
        response = self.client.post(reverse("santa:delete_configuration_rule", args=(configuration.pk, rule.pk)),
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_rules.html")
        self.assertFalse(any(rule.target.identifier == binary_hash for rule in response.context["object_list"]))

    def test_pick_rule_binary_access_denied(self):
        configuration = self._force_configuration()
        self._login("santa.add_configuration", "santa.view_configuration")
        response = self.client.get(reverse("santa:pick_rule_binary", args=(configuration.pk,)),
                                   {"name": self.file_name})
        self.assertEqual(response.status_code, 403)

    def test_pick_rule_binary(self):
        configuration = self._force_configuration()
        self._login("santa.add_rule")
        response = self.client.get(reverse("santa:pick_rule_binary", args=(configuration.pk,)),
                                   {"name": self.file_name})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/pick_rule_binary.html")
        binaries = response.context["binaries"]
        self.assertEqual(binaries, [(self.file, None)])
        self.assertContains(response, self.file.sha_256)

    def test_pick_rule_bundle_access_denied(self):
        configuration = self._force_configuration()
        self._login("santa.add_configuration", "santa.view_configuration")
        response = self.client.get(reverse("santa:pick_rule_bundle", args=(configuration.pk,)),
                                   {"name": self.file_bundle_name})
        self.assertEqual(response.status_code, 403)

    def test_pick_rule_bundle_not_ready(self):
        configuration = self._force_configuration()
        bundle = self._force_bundle()
        self._login("santa.add_rule")
        response = self.client.get(reverse("santa:pick_rule_bundle", args=(configuration.pk,)),
                                   {"name": self.file_bundle_name})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/pick_rule_bundle.html")
        self.assertEqual(response.context["bundles"], [(bundle, None)])
        self.assertContains(response, "Bundle not uploaded yet")
        self.assertNotContains(response, "Create rule")

    def test_pick_rule_bundle(self):
        configuration = self._force_configuration()
        bundle = self._force_bundle()
        bundle.binary_targets.add(self.file_target)
        bundle.uploaded_at = datetime.datetime.now()
        bundle.save()
        self._login("santa.add_rule")
        response = self.client.get(reverse("santa:pick_rule_bundle", args=(configuration.pk,)),
                                   {"name": self.file_bundle_name})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/pick_rule_bundle.html")
        self.assertEqual(response.context["bundles"], [(bundle, None)])
        self.assertNotContains(response, "Bundle not uploaded yet")
        self.assertContains(response, "Create rule")

    def test_pick_rule_certificate_access_denied(self):
        configuration = self._force_configuration()
        self._login("santa.add_configuration", "santa.view_configuration")
        response = self.client.get(reverse("santa:pick_rule_certificate", args=(configuration.pk,)),
                                   {"query": self.file_team_id})
        self.assertEqual(response.status_code, 403)

    def test_pick_rule_certificate(self):
        configuration = self._force_configuration()
        self._login("santa.add_rule")
        response = self.client.get(reverse("santa:pick_rule_certificate", args=(configuration.pk,)),
                                   {"query": self.file_team_id})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/pick_rule_certificate.html")
        certificates = response.context["certificates"]
        self.assertEqual(certificates, [(self.file.signed_by, None)])

    def test_pick_rule_team_id_access_denied(self):
        configuration = self._force_configuration()
        self._login("santa.add_configuration", "santa.view_configuration")
        response = self.client.get(reverse("santa:pick_rule_team_id", args=(configuration.pk,)),
                                   {"query": self.file_team_id})
        self.assertEqual(response.status_code, 403)

    def test_pick_rule_team_id(self):
        configuration = self._force_configuration()
        self._login("santa.add_rule")
        response = self.client.get(reverse("santa:pick_rule_team_id", args=(configuration.pk,)),
                                   {"query": self.file_team_id})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/pick_rule_team_id.html")
        team_ids = response.context["team_ids"]
        self.assertEqual(len(team_ids), 1)
        self.assertEqual(team_ids[0][0].organizational_unit, self.file_team_id)

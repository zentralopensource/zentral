import datetime
from functools import reduce
import operator
import plistlib
import urllib.parse
from accounts.models import User
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.test import TestCase, override_settings
from django.utils.crypto import get_random_string
from zentral.conf import settings
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit, File, Tag
from zentral.contrib.santa.models import Bundle, Enrollment, Rule, Target
from zentral.core.events.base import AuditEvent
from .utils import (force_configuration,
                    force_realm, force_realm_group, force_realm_user, force_voting_group,
                    new_cdhash, new_sha256, new_signing_id_identifier, new_team_id)


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class SantaSetupViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        # mbu
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
        # file tree
        cls.cdhash = new_cdhash()
        cls.file_sha256 = new_sha256()
        cls.file_name = get_random_string(12)
        cls.file_bundle_name = get_random_string(12)
        cls.file_cert_sha256 = new_sha256()
        cls.file_team_id = new_team_id()
        cls.file_signing_id = f"{cls.file_team_id}:transcoderx"
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
            'cdhash': cls.cdhash,
            'sha_256': cls.file_sha256,
            'signing_id': cls.file_signing_id,
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
        cls.file_target = Target.objects.create(type=Target.Type.BINARY, identifier=cls.file_sha256)

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

    def _force_enrollment(self, voting_realm=None):
        configuration = force_configuration(voting_realm=voting_realm)
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=self.mbu)
        enrollment = Enrollment.objects.create(configuration=configuration, secret=enrollment_secret)
        return configuration, enrollment

    def _force_bundle(self, uploaded=False):
        bundle_target = Target.objects.create(type=Target.Type.BUNDLE, identifier=new_sha256())
        return Bundle.objects.create(
            target=bundle_target,
            executable_rel_path=get_random_string(12),
            bundle_id=self.file.bundle.bundle_id,
            name=self.file_bundle_name,
            version=self.file.bundle.bundle_version,
            version_str=self.file.bundle.bundle_version_str,
            binary_count=1,
            uploaded_at=datetime.datetime.utcnow() if uploaded else None,
        )

    def _force_rule(self, target_type, configuration=None, target_identifier=None, policy=Rule.Policy.ALLOWLIST):
        if configuration is None:
            configuration = force_configuration()
        if target_identifier is None:
            if target_type == Target.Type.TEAM_ID:
                target_identifier = new_team_id()
            elif target_type == Target.Type.CDHASH:
                target_identifier = new_cdhash()
            elif target_type == Target.Type.SIGNING_ID:
                target_identifier = new_signing_id_identifier()
            else:
                target_identifier = new_sha256()
        target = Target.objects.create(type=target_type, identifier=target_identifier)
        return Rule.objects.create(configuration=configuration, target=target, policy=policy)

    # index

    def test_index_redirect(self):
        self._login_redirect(reverse("santa:index"))

    def test_index_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:index"))
        self.assertEqual(response.status_code, 403)

    def test_index(self):
        configuration = force_configuration()

        self._login("santa.view_configuration")
        response = self.client.get(reverse("santa:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/index.html")
        # 1 configuration
        self.assertContains(response, "Configuration (1)")
        self.assertContains(response, configuration.name)
        # no perms, no targets
        self.assertNotContains(response, "Collected targets (5)")

        self._login("santa.view_target")
        response = self.client.get(reverse("santa:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/index.html")
        # no perms, no configuration
        self.assertNotContains(response, "Configuration (1)")
        self.assertNotContains(response, configuration.name)
        # 1 binary, 1 cdhash, 1 certificate, 1 team ID, 1 signing ID
        self.assertContains(response, "Collected targets (5)")

    # configurations

    def test_configurations_redirect(self):
        self._login_redirect(reverse("santa:configuration_list"))

    def test_configurations_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:configuration_list"))
        self.assertEqual(response.status_code, 403)

    def test_configurations(self):
        configuration = force_configuration()
        self._login("santa.view_configuration")
        response = self.client.get(reverse("santa:configuration_list"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_list.html")
        self.assertContains(response, configuration.name)

    # configuration

    def test_configuration_redirect(self):
        configuration = force_configuration()
        self._login_redirect(configuration.get_absolute_url())

    def test_configuration_permission_denied(self):
        configuration = force_configuration()
        self._login()
        response = self.client.get(configuration.get_absolute_url())
        self.assertEqual(response.status_code, 403)

    def test_configuration_without_event_links(self):
        configuration = force_configuration()
        self._login("santa.view_configuration")
        response = self.client.get(configuration.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_detail.html")
        self.assertNotContains(response, reverse("santa:configuration_events",
                                                 args=(configuration.pk,)))
        self.assertNotContains(response, reverse("santa:configuration_events_store_redirect",
                                                 args=(configuration.pk,)))

    def test_configuration_with_event_links(self):
        configuration = force_configuration()
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
        configuration = force_configuration()
        self._login_redirect(reverse("santa:configuration_events", args=(configuration.pk,)))

    def test_configuration_events_permission_denied(self):
        configuration = force_configuration()
        self._login("santa.view_configuration")
        response = self.client.get(reverse("santa:configuration_events", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.get_aggregated_object_event_counts")
    def test_configuration_events_ok(self, get_aggregated_object_event_counts):
        get_aggregated_object_event_counts.return_value = {}
        configuration = force_configuration()
        self._login("santa.view_configuration",
                    "santa.view_enrollment",
                    "santa.view_rule",
                    "santa.view_ruleset")
        response = self.client.get(reverse("santa:configuration_events", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_events.html")

    def test_fetch_configuration_events_redirect(self):
        configuration = force_configuration()
        self._login_redirect(reverse("santa:fetch_configuration_events", args=(configuration.pk,)))

    def test_fetch_configuration_events_permission_denied(self):
        configuration = force_configuration()
        self._login("santa.view_rule")
        response = self.client.get(reverse("santa:fetch_configuration_events", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.fetch_object_events")
    def test_fetch_configuration_events_ok(self, fetch_object_events):
        fetch_object_events.return_value = ([], None)
        configuration = force_configuration()
        self._login("santa.view_configuration",
                    "santa.view_enrollment",
                    "santa.view_rule",
                    "santa.view_ruleset")
        response = self.client.get(reverse("santa:fetch_configuration_events", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/stores/events_events.html")

    # create configuration

    def test_create_configuration_redirect(self):
        self._login_redirect(reverse("santa:create_configuration"))

    def test_create_configuration_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:create_configuration"))
        self.assertEqual(response.status_code, 403)

    def test_get_create_configuration_view(self):
        self._login("santa.add_configuration")
        response = self.client.get(reverse("santa:create_configuration"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_form.html")
        self.assertContains(response, "Santa configuration")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_post_create_configuration_view(self, post_event):
        self._login("santa.add_configuration", "santa.view_configuration")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("santa:create_configuration"),
                                        {"name": name,
                                         "batch_size": 50,
                                         "client_mode": "1",
                                         "full_sync_interval": 602,
                                         "allow_unknown_shard": 87,
                                         "enable_all_event_upload_shard": 65,
                                         "sync_incident_severity": 0,
                                         }, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "santa/configuration_detail.html")
        self.assertContains(response, name)
        configuration = response.context["object"]
        self.assertEqual(configuration.name, name)
        self.assertEqual(configuration.full_sync_interval, 602)
        self.assertEqual(configuration.allow_unknown_shard, 87)
        self.assertEqual(configuration.enable_all_event_upload_shard, 65)
        self.assertEqual(configuration.sync_incident_severity, 0)
        self.assertFalse(configuration.block_usb_mount)
        self.assertEqual(configuration.remount_usb_mode, [])
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "santa.configuration",
                 "pk": str(configuration.pk),
                 "new_value": {
                     "pk": configuration.pk,
                     "name": name,
                     "client_mode": "Monitor",
                     "client_certificate_auth": False,
                     "batch_size": 50,
                     "full_sync_interval": 602,
                     "enable_bundles": False,
                     "enable_transitive_rules": False,
                     "allowed_path_regex": "",
                     "blocked_path_regex": "",
                     "block_usb_mount": False,
                     "remount_usb_mode": [],
                     "allow_unknown_shard": 87,
                     "enable_all_event_upload_shard": 65,
                     "sync_incident_severity": 0,
                     "voting_realm": None,
                     "banned_threshold": -26,
                     "default_ballot_target_types": [],
                     "default_voting_weight": 0,
                     "globally_allowlisted_threshold": 50,
                     "partially_allowlisted_threshold": 5,
                     "created_at": configuration.created_at,
                     "updated_at": configuration.updated_at
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"santa_configuration": [str(configuration.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["santa", "zentral"])

    # update configuration

    def test_update_configuration_redirect(self):
        configuration = force_configuration()
        self._login_redirect(reverse("santa:update_configuration", args=(configuration.pk,)))

    def test_post_update_configuration_view_permission_denied(self):
        self._login("santa.add_configuration", "santa.view_configuration")
        configuration = force_configuration()
        response = self.client.post(reverse("santa:update_configuration", args=(configuration.pk,)),
                                    {"name": configuration.name,
                                     "batch_size": 50,
                                     "client_mode": "1",
                                     "full_sync_interval": 603,
                                     "allow_unknown_shard": 91,
                                     "enable_all_event_upload_shard": 76,
                                     "sync_incident_severity": 300,
                                     }, follow=True)
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_post_update_configuration_view(self, post_event):
        configuration = force_configuration()
        prev_updated_at = configuration.updated_at
        self._login("santa.change_configuration", "santa.view_configuration")
        realm = force_realm()
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("santa:update_configuration", args=(configuration.pk,)),
                                        {"name": configuration.name,
                                         "batch_size": 50,
                                         "client_mode": "1",
                                         "full_sync_interval": 603,
                                         "allow_unknown_shard": 91,
                                         "enable_all_event_upload_shard": 76,
                                         "sync_incident_severity": 300,
                                         "block_usb_mount": "on",
                                         "remount_usb_mode": "rdonly, noexec",
                                         "voting_realm": realm.pk,
                                         "banned_threshold": -50,
                                         "default_ballot_target_types": ["METABUNDLE", "SIGNINGID"],
                                         "default_voting_weight": 1,
                                         "globally_allowlisted_threshold": 500,
                                         "partially_allowlisted_threshold": 100,
                                         }, follow=True)
        self.assertTemplateUsed(response, "santa/configuration_detail.html")
        self.assertEqual(len(callbacks), 1)
        configuration = response.context["object"]
        self.assertEqual(configuration.full_sync_interval, 603)
        self.assertEqual(configuration.allow_unknown_shard, 91)
        self.assertEqual(configuration.enable_all_event_upload_shard, 76)
        self.assertEqual(configuration.sync_incident_severity, 300)
        self.assertTrue(configuration.block_usb_mount)
        self.assertEqual(configuration.remount_usb_mode, ["rdonly", "noexec"])
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "santa.configuration",
                 "pk": str(configuration.pk),
                 "prev_value": {
                     "pk": configuration.pk,
                     "name": configuration.name,
                     "client_mode": "Monitor",
                     "client_certificate_auth": False,
                     "batch_size": 50,
                     "full_sync_interval": 600,
                     "enable_bundles": False,
                     "enable_transitive_rules": False,
                     "allowed_path_regex": "",
                     "blocked_path_regex": "",
                     "block_usb_mount": False,
                     "remount_usb_mode": [],
                     "allow_unknown_shard": 100,
                     "enable_all_event_upload_shard": 0,
                     "sync_incident_severity": 0,
                     "voting_realm": None,
                     "banned_threshold": -26,
                     "default_ballot_target_types": [],
                     "default_voting_weight": 0,
                     "globally_allowlisted_threshold": 50,
                     "partially_allowlisted_threshold": 5,
                     "created_at": configuration.created_at,
                     "updated_at": prev_updated_at
                 },
                 "new_value": {
                     "pk": configuration.pk,
                     "name": configuration.name,
                     "client_mode": "Monitor",
                     "client_certificate_auth": False,
                     "batch_size": 50,
                     "full_sync_interval": 603,
                     "enable_bundles": False,
                     "enable_transitive_rules": False,
                     "allowed_path_regex": "",
                     "blocked_path_regex": "",
                     "block_usb_mount": True,
                     "remount_usb_mode": ["rdonly", "noexec"],
                     "allow_unknown_shard": 91,
                     "enable_all_event_upload_shard": 76,
                     "sync_incident_severity": 300,
                     "voting_realm": {"name": realm.name,
                                      "pk": str(realm.pk)},
                     "banned_threshold": -50,
                     "default_ballot_target_types": ["METABUNDLE", "SIGNINGID"],
                     "default_voting_weight": 1,
                     "globally_allowlisted_threshold": 500,
                     "partially_allowlisted_threshold": 100,
                     "created_at": configuration.created_at,
                     "updated_at": configuration.updated_at
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"santa_configuration": [str(configuration.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["santa", "zentral"])

    def test_post_update_configuration_view_remount_usb_mode_error(self):
        configuration = force_configuration()
        self._login("santa.change_configuration", "santa.view_configuration")
        response = self.client.post(reverse("santa:update_configuration", args=(configuration.pk,)),
                                    {"name": configuration.name,
                                     "batch_size": 50,
                                     "client_mode": "1",
                                     "full_sync_interval": 603,
                                     "allow_unknown_shard": 91,
                                     "enable_all_event_upload_shard": 76,
                                     "sync_incident_severity": 300,
                                     "remount_usb_mode": "rdonly, noexec"
                                     }, follow=True)
        self.assertTemplateUsed(response, "santa/configuration_form.html")
        self.assertFormError(response.context["form"],
                             "remount_usb_mode", "'Block USB mount' must be set to use this option")

    # enrollment

    def test_create_enrollment_redirect(self):
        configuration = force_configuration()
        self._login_redirect(reverse("santa:create_enrollment", args=(configuration.pk,)))

    def test_create_enrollment_permission_denied(self):
        configuration = force_configuration()
        self._login()
        response = self.client.get(reverse("santa:create_enrollment", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_create_enrollment_view(self):
        configuration = force_configuration()
        self._login("santa.add_enrollment")
        response = self.client.get(reverse("santa:create_enrollment", args=(configuration.pk,)))
        self.assertTemplateUsed(response, "santa/enrollment_form.html")
        self.assertContains(response, "Create enrollment")
        self.assertContains(response, configuration.name)

    def test_post_create_enrollment_view_errors(self):
        configuration = force_configuration()
        self._login("santa.add_enrollment", "santa.view_configuration")
        response = self.client.post(reverse("santa:create_enrollment", args=(configuration.pk,)),
                                    {"secret-meta_business_unit": self.mbu.pk,
                                     "secret-quota": "abcd",
                                     "configuration": configuration.pk}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response.context["form"], "meta_business_unit",
                             "Select a valid choice. That choice is not one of the available choices.")
        self.assertFormError(response.context["form"], "quota",
                             "Enter a whole number.")

    def test_post_create_enrollment_view_no_view_enrollment_perm(self):
        configuration = force_configuration()
        self.mbu.create_enrollment_business_unit()
        self._login("santa.add_enrollment", "santa.view_configuration")
        response = self.client.post(reverse("santa:create_enrollment", args=(configuration.pk,)),
                                    {"secret-meta_business_unit": self.mbu.pk,
                                     "configuration": configuration.pk}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_detail.html")
        self.assertEqual(response.context["object"], configuration)
        # no view enrollment perm!
        self.assertNotIn("enrollments", response.context)

    def test_post_create_enrollment_view(self):
        configuration = force_configuration()
        self.mbu.create_enrollment_business_unit()
        self._login("santa.add_enrollment", "santa.view_enrollment", "santa.view_configuration")
        response = self.client.post(reverse("santa:create_enrollment", args=(configuration.pk,)),
                                    {"secret-meta_business_unit": self.mbu.pk,
                                     "configuration": configuration.pk}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_detail.html")
        self.assertEqual(response.context["object"], configuration)
        # with view enrollment perm
        enrollment = response.context["enrollments"][0]
        self.assertEqual(enrollment.configuration, configuration)
        self.assertContains(response, enrollment.secret.meta_business_unit.name)
        self.assertContains(response, reverse("santa_api:enrollment_plist", args=(enrollment.pk,)))
        self.assertContains(response, reverse("santa_api:enrollment_configuration_profile", args=(enrollment.pk,)))

    def test_enrollment_plist_permission_denied(self):
        _, enrollment = self._force_enrollment()
        self._login()
        response = self.client.get(reverse("santa_api:enrollment_plist", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_enrollment_plist(self):
        configuration, enrollment = self._force_enrollment()
        self._login("santa.view_enrollment")
        response = self.client.get(reverse("santa_api:enrollment_plist", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "application/x-plist")
        plist_config = plistlib.loads(response.content)
        self.assertEqual(
            plist_config,
            {'ClientMode': configuration.client_mode,
             'SyncBaseURL': f'https://{settings["api"]["fqdn"]}/public/santa/sync/',
             'SyncExtraHeaders': {
                 'Zentral-Authorization': f'Bearer {enrollment.secret.secret}'
             }}
        )

    def test_enrollment_with_voting_plist(self):
        realm = force_realm(user_portal=True)
        configuration, enrollment = self._force_enrollment(voting_realm=realm)
        self._login("santa.view_enrollment")
        response = self.client.get(reverse("santa_api:enrollment_plist", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "application/x-plist")
        plist_config = plistlib.loads(response.content)
        self.assertEqual(
            plist_config,
            {'ClientMode': configuration.client_mode,
             'EventDetailText': 'More info',
             'EventDetailURL': f'https://zentral/public/realms/{realm.pk}/up/santa/event_detail/'
                               '?bofid=%bundle_or_file_identifier%&fid=%file_identifier%&mid=%machine_id%'
                               '&tid=%team_id%&sid=%signing_id%&cdh=%cdhash%',
             'SyncBaseURL': f'https://{settings["api"]["fqdn"]}/public/santa/sync/',
             'SyncExtraHeaders': {
                 'Zentral-Authorization': f'Bearer {enrollment.secret.secret}'
             }}
        )

    def test_enrollment_configuration_profile_permission_denied(self):
        _, enrollment = self._force_enrollment()
        self._login()
        response = self.client.get(reverse("santa_api:enrollment_configuration_profile", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_enrollment_configuration_profile(self):
        _, enrollment = self._force_enrollment()
        self._login("santa.view_enrollment")
        response = self.client.get(reverse("santa_api:enrollment_configuration_profile", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "application/octet-stream")

    # create voting group

    def test_create_voting_group_redirect(self):
        configuration = force_configuration()
        self._login_redirect(reverse("santa:create_voting_group", args=(configuration.pk,)))

    def test_create_voting_group_permission_denied(self):
        configuration = force_configuration()
        self._login()
        response = self.client.get(reverse("santa:create_voting_group", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_create_voting_group_get(self):
        configuration = force_configuration()
        realm_group = force_realm_group()
        self._login("santa.add_votinggroup")
        response = self.client.get(reverse("santa:create_voting_group", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/votinggroup_form.html")
        self.assertContains(response, realm_group.realm.name)
        self.assertContains(response, realm_group.display_name)

    def test_create_voting_group_post(self):
        configuration = force_configuration()
        realm_group = force_realm_group()
        self._login("santa.add_votinggroup", "santa.view_configuration", "santa.view_votinggroup")
        response = self.client.post(reverse("santa:create_voting_group", args=(configuration.pk,)),
                                    {"realm_group": realm_group.pk,
                                     "can_unflag_target": "on",
                                     "can_mark_malware": "on",
                                     "can_reset_target": "on",
                                     "ballot_target_types": ["METABUNDLE", "SIGNINGID"],
                                     "voting_weight": 5},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_detail.html")
        self.assertContains(response, realm_group.display_name)
        self.assertEqual(configuration.votinggroup_set.count(), 1)
        voting_group = configuration.votinggroup_set.first()
        self.assertTrue(voting_group.can_unflag_target)
        self.assertTrue(voting_group.can_mark_malware)
        self.assertTrue(voting_group.can_reset_target)
        self.assertEqual(sorted(voting_group.ballot_target_types), ["METABUNDLE", "SIGNINGID"])
        self.assertEqual(voting_group.voting_weight, 5)

    def test_create_voting_group_post_realm_group_conflict(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        voting_group = force_voting_group(configuration, realm_user)
        self._login("santa.add_votinggroup", "santa.view_configuration", "santa.view_votinggroup")
        response = self.client.post(reverse("santa:create_voting_group", args=(configuration.pk,)),
                                    {"realm_group": voting_group.realm_group.pk,  # conflict
                                     "can_unflag_target": "on",
                                     "can_mark_malware": "on",
                                     "can_reset_target": "on",
                                     "ballot_target_types": ["SIGNINGID"],
                                     "voting_weight": 17},
                                    follow=True,
                                    )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/votinggroup_form.html")
        self.assertFormError(response.context["form"], "realm_group",
                             "Select a valid choice. That choice is not one of the available choices.")

    # update voting group

    def test_update_voting_group_redirect(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        voting_group = force_voting_group(configuration, realm_user)
        self._login_redirect(reverse("santa:update_voting_group", args=(configuration.pk, voting_group.pk)))

    def test_update_voting_group_permission_denied(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        voting_group = force_voting_group(configuration, realm_user)
        self._login()
        response = self.client.get(reverse("santa:update_voting_group", args=(configuration.pk, voting_group.pk)))
        self.assertEqual(response.status_code, 403)

    def test_update_voting_group_get(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        voting_group = force_voting_group(configuration, realm_user)
        self._login("santa.change_votinggroup")
        response = self.client.get(reverse("santa:update_voting_group", args=(configuration.pk, voting_group.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/votinggroup_form.html")

    def test_update_voting_group_post(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        voting_group = force_voting_group(configuration, realm_user)
        realm_group = voting_group.realm_group
        self._login("santa.change_votinggroup", "santa.view_configuration", "santa.view_votinggroup")
        response = self.client.post(reverse("santa:update_voting_group", args=(configuration.pk, voting_group.pk)),
                                    {"realm_group": realm_group.pk,
                                     "can_unflag_target": "on",
                                     "can_mark_malware": "on",
                                     "can_reset_target": "on",
                                     "ballot_target_types": ["SIGNINGID"],
                                     "voting_weight": 17},
                                    follow=True,
                                    )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_detail.html")
        self.assertContains(response, realm_group.display_name)
        self.assertEqual(configuration.votinggroup_set.count(), 1)
        voting_group_2 = configuration.votinggroup_set.first()
        self.assertEqual(voting_group, voting_group_2)
        voting_group.refresh_from_db()
        self.assertTrue(voting_group.can_unflag_target)
        self.assertTrue(voting_group.can_mark_malware)
        self.assertTrue(voting_group.can_reset_target)
        self.assertEqual(sorted(voting_group.ballot_target_types), ["SIGNINGID"])
        self.assertEqual(voting_group.voting_weight, 17)

    def test_update_voting_group_post_realm_group_conflict(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        voting_group = force_voting_group(configuration, realm_user)
        realm2, realm_user2 = force_realm_user()
        voting_group_2 = force_voting_group(configuration, realm_user2)
        self._login("santa.change_votinggroup", "santa.view_configuration", "santa.view_votinggroup")
        response = self.client.post(reverse("santa:update_voting_group", args=(configuration.pk, voting_group.pk)),
                                    {"realm_group": voting_group_2.realm_group.pk,  # conflict
                                     "can_unflag_target": "on",
                                     "can_mark_malware": "on",
                                     "can_reset_target": "on",
                                     "ballot_target_types": ["SIGNINGID"],
                                     "voting_weight": 17},
                                    follow=True,
                                    )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/votinggroup_form.html")
        self.assertFormError(response.context["form"], "realm_group",
                             "Select a valid choice. That choice is not one of the available choices.")

    # delete voting group

    def test_delete_voting_group_redirect(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        voting_group = force_voting_group(configuration, realm_user)
        self._login_redirect(reverse("santa:delete_voting_group", args=(configuration.pk, voting_group.pk)))

    def test_delete_voting_group_permission_denied(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        voting_group = force_voting_group(configuration, realm_user)
        self._login()
        response = self.client.get(reverse("santa:delete_voting_group", args=(configuration.pk, voting_group.pk)))
        self.assertEqual(response.status_code, 403)

    def test_delete_voting_group_get(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        voting_group = force_voting_group(configuration, realm_user)
        self._login("santa.delete_votinggroup")
        response = self.client.get(reverse("santa:delete_voting_group", args=(configuration.pk, voting_group.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/votinggroup_confirm_delete.html")

    def test_delete_voting_group_post(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        voting_group = force_voting_group(configuration, realm_user)
        self.assertTrue(configuration.votinggroup_set.filter(pk=voting_group.pk).exists())
        self._login("santa.delete_votinggroup", "santa.view_configuration", "santa.view_votinggroup")
        response = self.client.post(reverse("santa:delete_voting_group", args=(configuration.pk, voting_group.pk)),
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_detail.html")
        self.assertFalse(configuration.votinggroup_set.filter(pk=voting_group.pk).exists())
        self.assertNotContains(response, voting_group.realm_group.display_name)

    # configuration rules

    def test_configuration_rules_redirect(self):
        configuration = force_configuration()
        self._login_redirect(reverse("santa:configuration_rules", args=(configuration.pk,)))

    def test_configuration_rules_permission_denied(self):
        configuration = force_configuration()
        self._login()
        response = self.client.get(reverse("santa:configuration_rules", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_configuration_rules_no_rules(self):
        configuration = force_configuration()
        self._login("santa.view_rule")
        response = self.client.get(reverse("santa:configuration_rules", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_rules.html")
        self.assertNotContains(response, "We didn't find any item related to your search")
        self.assertNotContains(response, reverse("santa:configuration_rules",
                                                 args=(configuration.pk,)) + '">all the items')

    def test_configuration_rules_binary_search(self):
        rule = self._force_rule(target_type=Target.Type.BINARY)
        self._login("santa.view_rule")
        response = self.client.get(reverse("santa:configuration_rules", args=(rule.configuration.pk,)),
                                   {"identifier": rule.target.identifier})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_rules.html")
        self.assertContains(response, rule.target.identifier)
        self.assertNotContains(response, reverse("santa:configuration_rules",
                                                 args=(rule.configuration.pk,)) + '">all the items')

    def test_configuration_rules_no_result(self):
        rule = self._force_rule(target_type=Target.Type.BINARY)
        self._login("santa.view_rule")
        response = self.client.get(reverse("santa:configuration_rules", args=(rule.configuration.pk,)),
                                   {"identifier": "does not exists"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_rules.html")
        self.assertContains(response, "We didn't find any item related to your search")
        self.assertContains(response, reverse("santa:configuration_rules",
                                              args=(rule.configuration.pk,)) + '">all the items')

    def test_configuration_three_cdhash_rules(self):
        configuration = force_configuration()
        for _ in range(3):
            self._force_rule(target_type=Target.Type.CDHASH, configuration=configuration)
        self._force_rule(target_type=Target.Type.SIGNING_ID, configuration=configuration)
        self._login("santa.view_rule")
        self.user.items_per_page = 1
        self.user.save()
        response = self.client.get(reverse("santa:configuration_rules", args=(configuration.pk,)),
                                   {"target_type": Target.Type.CDHASH, "page": 2})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_rules.html")
        self.assertContains(response, "Rules (3)")
        self.assertEqual(response.context["next_url"], "?target_type=CDHASH&page=3")
        self.assertEqual(response.context["reset_link"], "?target_type=CDHASH")
        self.assertEqual(response.context["previous_url"], "?target_type=CDHASH&page=1")

    # create configuration rule

    def test_create_configuration_rule_redirect(self):
        configuration = force_configuration()
        self._login_redirect(reverse("santa:create_configuration_rule", args=(configuration.pk,)))

    def test_create_configuration_rule_permission_denied(self):
        self._login("santa.add_configuration", "santa.view_configuration")
        configuration = force_configuration()
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                    {"target_type": Target.Type.BINARY,
                                     "target_identifier": new_sha256(),
                                     "policy": Rule.Policy.ALLOWLIST},
                                    follow=True)
        self.assertEqual(response.status_code, 403)

    def test_create_configuration_rules(self):
        self._login("santa.add_configuration", "santa.view_configuration")
        configuration = force_configuration()
        # create
        self._login("santa.add_rule", "santa.view_rule")
        for target_identifier, target_type in (
            (new_sha256(), Target.Type.BINARY),
            (new_sha256(), Target.Type.CERTIFICATE),
            (new_cdhash(), Target.Type.CDHASH),
            (new_team_id(), Target.Type.TEAM_ID),
            (new_signing_id_identifier(), Target.Type.SIGNING_ID),
        ):
            description = get_random_string(12)
            response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                        {"target_type": target_type,
                                         "target_identifier": target_identifier,
                                         "policy": Rule.Policy.ALLOWLIST,
                                         "description": description}, follow=True)
            self.assertEqual(response.status_code, 200)
            self.assertTemplateUsed(response, "santa/configuration_rules.html")
            self.assertContains(response, target_identifier)
            self.assertContains(response, description)
            rule = response.context["object_list"][0]
            self.assertEqual(rule.configuration, configuration)
            self.assertEqual(rule.target.identifier, target_identifier)
            self.assertEqual(rule.target.type, target_type)
            self.assertEqual(rule.policy, Rule.Policy.ALLOWLIST)
            self.assertEqual(rule.custom_msg, "")
            self.assertEqual(rule.description, description)
            self.assertEqual(rule.serial_numbers, [])
            self.assertEqual(rule.primary_users, [])
            self.assertContains(response, description)

    def test_create_configuration_binary_rule_error(self):
        self._login("santa.add_configuration", "santa.view_configuration")
        configuration = force_configuration()
        # create
        self._login("santa.add_rule", "santa.view_rule")
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                    {"target_type": Target.Type.BINARY,
                                     "target_identifier": get_random_string(12),
                                     "policy": Rule.Policy.ALLOWLIST},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/rule_form.html")
        self.assertFormError(response.context["form"], "target_identifier", "Invalid BINARY identifier")

    def test_create_configuration_binary_rule_preselected_get_ok(self):
        configuration = force_configuration()
        self._login("santa.add_rule")
        response = self.client.get(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                   {"bin": self.file.pk})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/rule_form.html")
        self.assertContains(response, self.file.sha_256)
        self.assertContains(response, "Add Santa binary rule")

    def test_create_configuration_binary_rule_preselected_post_ok(self):
        configuration = force_configuration()
        self._login("santa.add_rule", "santa.view_rule")
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,))
                                    + "?" + urllib.parse.urlencode({"bin": self.file.pk}),
                                    {"policy": Rule.Policy.ALLOWLIST},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_rules.html")
        self.assertContains(response, self.file.sha_256)
        rule = response.context["object_list"][0]
        self.assertEqual(rule.configuration, configuration)
        self.assertEqual(rule.target.identifier, self.file.sha_256)
        self.assertEqual(rule.target.type, Target.Type.BINARY)

    def test_create_configuration_cdhash_rule_error(self):
        self._login("santa.add_configuration", "santa.view_configuration")
        configuration = force_configuration()
        # create
        self._login("santa.add_rule", "santa.view_rule")
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                    {"target_type": Target.Type.CDHASH,
                                     "target_identifier": get_random_string(12),
                                     "policy": Rule.Policy.ALLOWLIST},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/rule_form.html")
        self.assertFormError(response.context["form"], "target_identifier", "Invalid CDHASH identifier")

    def test_create_configuration_cdhash_rule_preselected_get_ok(self):
        configuration = force_configuration()
        self._login("santa.add_rule")
        cdhash = new_cdhash()
        response = self.client.get(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                   {"cdhash": cdhash})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/rule_form.html")
        self.assertContains(response, cdhash)
        self.assertContains(response, "Add Santa cdhash rule")

    def test_create_configuration_cdhash_rule_preselected_post_ok(self):
        configuration = force_configuration()
        self._login("santa.add_rule", "santa.view_rule")
        cdhash = new_cdhash()
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,))
                                    + "?" + urllib.parse.urlencode({"cdhash": cdhash}),
                                    {"policy": Rule.Policy.ALLOWLIST},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_rules.html")
        self.assertContains(response, cdhash)
        rule = response.context["object_list"][0]
        self.assertEqual(rule.configuration, configuration)
        self.assertEqual(rule.target.identifier, cdhash)
        self.assertEqual(rule.target.type, Target.Type.CDHASH)

    def test_create_configuration_certificate_rule_preselected_get_ok(self):
        configuration = force_configuration()
        self._login("santa.add_rule")
        response = self.client.get(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                   {"cert": self.file.signed_by.pk})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/rule_form.html")
        self.assertContains(response, self.file.signed_by.sha_256)
        self.assertContains(response, "Add Santa certificate rule")

    def test_create_configuration_certificate_rule_preselected_post_ok(self):
        configuration = force_configuration()
        self._login("santa.add_rule", "santa.view_rule")
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,))
                                    + "?" + urllib.parse.urlencode({"cert": self.file.signed_by.pk}),
                                    {"policy": Rule.Policy.ALLOWLIST},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_rules.html")
        self.assertContains(response, self.file.signed_by.sha_256)
        rule = response.context["object_list"][0]
        self.assertEqual(rule.configuration, configuration)
        self.assertEqual(rule.target.identifier, self.file.signed_by.sha_256)
        self.assertEqual(rule.target.type, Target.Type.CERTIFICATE)

    def test_create_configuration_signing_id_rule_error(self):
        self._login("santa.add_configuration", "santa.view_configuration")
        configuration = force_configuration()
        # create
        self._login("santa.add_rule", "santa.view_rule")
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                    {"target_type": Target.Type.SIGNING_ID,
                                     "target_identifier": get_random_string(12),
                                     "policy": Rule.Policy.ALLOWLIST},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/rule_form.html")
        self.assertFormError(response.context["form"], "target_identifier", "Invalid SIGNINGID identifier")

    def test_create_configuration_signing_id_rule_preselected_get_ok(self):
        configuration = force_configuration()
        self._login("santa.add_rule")
        response = self.client.get(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                   {"sig": "43AQ936H96:org.mozilla.firefox"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/rule_form.html")
        self.assertContains(response, "43AQ936H96:org.mozilla.firefox")
        self.assertContains(response, "Add Santa signing ID rule")

    def test_create_configuration_signing_id_rule_preselected_post_ok(self):
        configuration = force_configuration()
        self._login("santa.add_rule", "santa.view_rule")
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,))
                                    + "?" + urllib.parse.urlencode({"sig": "43AQ936H96:org.mozilla.firefox"}),
                                    {"policy": Rule.Policy.ALLOWLIST},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_rules.html")
        self.assertContains(response, "43AQ936H96:org.mozilla.firefox")
        rule = response.context["object_list"][0]
        self.assertEqual(rule.configuration, configuration)
        self.assertEqual(rule.target.identifier, "43AQ936H96:org.mozilla.firefox")
        self.assertEqual(rule.target.type, Target.Type.SIGNING_ID)

    def test_create_configuration_team_id_rule_error(self):
        self._login("santa.add_configuration", "santa.view_configuration")
        configuration = force_configuration()
        # create
        self._login("santa.add_rule", "santa.view_rule")
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                    {"target_type": Target.Type.TEAM_ID,
                                     "target_identifier": get_random_string(12),
                                     "policy": Rule.Policy.ALLOWLIST},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/rule_form.html")
        self.assertFormError(response.context["form"], "target_identifier", "Invalid TEAMID identifier")

    def test_create_configuration_team_id_rule_preselected_get_ok(self):
        configuration = force_configuration()
        self._login("santa.add_rule")
        response = self.client.get(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                   {"tea": "JQ525L2MZD"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/rule_form.html")
        self.assertContains(response, "JQ525L2MZD")
        self.assertContains(response, "Add Santa team ID rule")

    def test_create_configuration_team_id_rule_preselected_post_ok(self):
        configuration = force_configuration()
        self._login("santa.add_rule", "santa.view_rule")
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,))
                                    + "?" + urllib.parse.urlencode({"tea": "JQ525L2MZD"}),
                                    {"policy": Rule.Policy.ALLOWLIST},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_rules.html")
        self.assertContains(response, "JQ525L2MZD")
        rule = response.context["object_list"][0]
        self.assertEqual(rule.configuration, configuration)
        self.assertEqual(rule.target.identifier, "JQ525L2MZD")
        self.assertEqual(rule.target.type, Target.Type.TEAM_ID)

    def test_create_configuration_team_id_rule_preselected_error(self):
        # This is a test for when a team ID is picked from the list of target
        # to create a rule, but … this is not a valid team ID.
        # This should never happen!
        configuration = force_configuration()
        self._login("santa.add_rule", "santa.view_rule")
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,))
                                    + "?" + urllib.parse.urlencode({"tea": "NOT_A_TEAM_ID"}),
                                    {"policy": Rule.Policy.ALLOWLIST},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/rule_form.html")
        self.assertFormError(response.context["form"],
                             None, "Invalid TEAMID identifier")

    def test_create_conflict_configuration_rule(self):
        self._login("santa.add_configuration", "santa.view_configuration",
                    "santa.add_rule", "santa.view_rule")
        configuration = force_configuration()
        # create
        binary_hash = new_sha256()
        self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                         {"target_type": Target.Type.BINARY,
                          "target_identifier": binary_hash,
                          "policy": Rule.Policy.ALLOWLIST}, follow=True)
        # conflict
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                    {"target_type": Target.Type.BINARY,
                                     "target_identifier": binary_hash,
                                     "policy": Rule.Policy.BLOCKLIST}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/rule_form.html")
        form = response.context["form"]
        self.assertEqual(form.errors, {'__all__': ['A rule for this target already exists']})

    def test_create_configuration_rule_scope_conflict(self):
        self._login("santa.add_configuration", "santa.view_configuration",
                    "santa.add_rule", "santa.view_rule")
        configuration = force_configuration()
        binary_hash = new_sha256()
        tags = [Tag.objects.create(name=get_random_string(32)) for _ in range(3)]
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                    {"target_type": Target.Type.BINARY,
                                     "target_identifier": binary_hash,
                                     "policy": Rule.Policy.ALLOWLIST,
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

    # update configuration rule

    def test_update_configuration_rule(self):
        self._login("santa.add_configuration", "santa.view_configuration",
                    "santa.add_rule", "santa.view_rule")
        configuration = force_configuration()
        # create
        binary_hash = new_sha256()
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(3)]
        excluded_tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(3)]
        serial_numbers = [get_random_string(12) for _ in range(3)]
        excluded_serial_numbers = [get_random_string(12) for _ in range(3)]
        primary_users = [get_random_string(12) for _ in range(3)]
        excluded_primary_users = [get_random_string(12) for _ in range(3)]
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                    {"target_type": Target.Type.BINARY,
                                     "target_identifier": binary_hash,
                                     "policy": Rule.Policy.ALLOWLIST,
                                     "excluded_tags": [t.pk for t in excluded_tags[:2]],
                                     "tags": [t.pk for t in tags[:2]],
                                     "serial_numbers": ",".join(serial_numbers[:2]),
                                     "excluded_serial_numbers": ",".join(excluded_serial_numbers[:2]),
                                     "primary_users": ",".join(primary_users[:2]),
                                     "excluded_primary_users": ",".join(excluded_primary_users[:2]),
                                     }, follow=True)
        rule = response.context["object_list"][0]
        # update
        custom_message = get_random_string(12)
        description = get_random_string(12)
        response = self.client.post(reverse("santa:update_configuration_rule", args=(configuration.pk, rule.pk)),
                                    {"target_type": Target.Type.BINARY,
                                     "target_identifier": binary_hash,
                                     "policy": Rule.Policy.BLOCKLIST,
                                     "custom_msg": custom_message,
                                     "description": description,
                                     "excluded_tags": [t.pk for t in excluded_tags[1:]],
                                     "tags": [t.pk for t in tags[1:]],
                                     "serial_numbers": ",".join(serial_numbers[1:]),
                                     "excluded_serial_numbers": ",".join(excluded_serial_numbers[1:]),
                                     "primary_users": ",".join(primary_users[1:]),
                                     "excluded_primary_users": ",".join(excluded_primary_users[1:]),
                                     }, follow=True)
        self.assertEqual(response.status_code, 403)
        self._login("santa.change_rule", "santa.view_rule")
        response = self.client.post(reverse("santa:update_configuration_rule", args=(configuration.pk, rule.pk)),
                                    {"target_type": Target.Type.BINARY,
                                     "target_identifier": binary_hash,
                                     "policy": Rule.Policy.BLOCKLIST,
                                     "custom_msg": custom_message,
                                     "description": description,
                                     "excluded_tags": [t.pk for t in excluded_tags[1:]],
                                     "tags": [t.pk for t in tags[1:]],
                                     "serial_numbers": ",".join(serial_numbers[1:]),
                                     "excluded_serial_numbers": ",".join(excluded_serial_numbers[1:]),
                                     "primary_users": ",".join(primary_users[1:]),
                                     "excluded_primary_users": ",".join(excluded_primary_users[1:]),
                                     }, follow=True)
        self.assertTemplateUsed(response, "santa/configuration_rules.html")
        rule = response.context["object_list"][0]
        self.assertEqual(rule.configuration, configuration)
        self.assertEqual(rule.target.identifier, binary_hash)
        self.assertEqual(rule.target.type, Target.Type.BINARY)
        self.assertEqual(rule.policy, Rule.Policy.BLOCKLIST)
        self.assertEqual(rule.custom_msg, custom_message)
        self.assertEqual(rule.description, description)
        self.assertEqual(sorted(rule.excluded_tags.all(), key=lambda t: t.pk),
                         sorted(excluded_tags[1:], key=lambda t: t.pk))
        self.assertEqual(sorted(rule.tags.all(), key=lambda t: t.pk),
                         sorted(tags[1:], key=lambda t: t.pk))
        self.assertEqual(sorted(rule.serial_numbers), sorted(serial_numbers[1:]))
        self.assertEqual(sorted(rule.excluded_serial_numbers), sorted(excluded_serial_numbers[1:]))
        self.assertEqual(sorted(rule.primary_users), sorted(primary_users[1:]))
        self.assertEqual(sorted(rule.excluded_primary_users), sorted(excluded_primary_users[1:]))

    def test_update_configuration_rule_scope_conflict(self):
        self._login("santa.add_configuration", "santa.view_configuration",
                    "santa.add_rule", "santa.view_rule", "santa.change_rule")
        configuration = force_configuration()
        # create
        binary_hash = new_sha256()
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                    {"target_type": Target.Type.BINARY,
                                     "target_identifier": binary_hash,
                                     "policy": Rule.Policy.ALLOWLIST}, follow=True)
        rule = response.context["object_list"][0]
        # update
        tags = [Tag.objects.create(name=get_random_string(32)) for _ in range(3)]
        response = self.client.post(reverse("santa:update_configuration_rule", args=(configuration.pk, rule.pk)),
                                    {"target_type": Target.Type.BINARY,
                                     "target_identifier": binary_hash,
                                     "policy": Rule.Policy.ALLOWLIST,
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

    # delete configuration rule

    def test_delete_configuration_rule(self):
        self._login("santa.add_configuration", "santa.view_configuration",
                    "santa.add_rule", "santa.view_rule")
        configuration = force_configuration()
        # create
        binary_hash = new_sha256()
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                    {"target_type": Target.Type.BINARY,
                                     "target_identifier": binary_hash,
                                     "policy": Rule.Policy.ALLOWLIST}, follow=True)
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

    # pick rule binary

    def test_pick_rule_binary_redirect(self):
        configuration = force_configuration()
        self._login_redirect(reverse("santa:pick_rule_binary", args=(configuration.pk,)))

    def test_pick_rule_binary_access_denied(self):
        configuration = force_configuration()
        self._login("santa.add_configuration", "santa.view_configuration")
        response = self.client.get(reverse("santa:pick_rule_binary", args=(configuration.pk,)),
                                   {"name": self.file_name})
        self.assertEqual(response.status_code, 403)

    def test_pick_rule_binary(self):
        configuration = force_configuration()
        self._login("santa.add_rule")
        response = self.client.get(reverse("santa:pick_rule_binary", args=(configuration.pk,)),
                                   {"name": self.file_name})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/pick_rule_binary.html")
        binaries = response.context["binaries"]
        self.assertEqual(binaries, [(self.file, None)])
        self.assertContains(response, self.file.sha_256)

    # pick rule cdhash

    def test_pick_rule_cdhash_redirect(self):
        configuration = force_configuration()
        self._login_redirect(reverse("santa:pick_rule_cdhash", args=(configuration.pk,)))

    def test_pick_rule_cdhash_access_denied(self):
        configuration = force_configuration()
        self._login("santa.add_configuration", "santa.view_configuration")
        response = self.client.get(reverse("santa:pick_rule_cdhash", args=(configuration.pk,)),
                                   {"query": self.cdhash})
        self.assertEqual(response.status_code, 403)

    def test_pick_rule_cdhash(self):
        configuration = force_configuration()
        self._login("santa.add_rule")
        response = self.client.get(reverse("santa:pick_rule_cdhash", args=(configuration.pk,)),
                                   {"query": self.cdhash})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/pick_rule_cdhash.html")
        cdhashes = response.context["cdhashes"]
        self.assertEqual(len(cdhashes), 1)
        self.assertEqual(cdhashes[0][0].cdhash, self.cdhash)

    # pick rule certificate

    def test_pick_rule_certificate_redirect(self):
        configuration = force_configuration()
        self._login_redirect(reverse("santa:pick_rule_certificate", args=(configuration.pk,)))

    def test_pick_rule_certificate_access_denied(self):
        configuration = force_configuration()
        self._login("santa.add_configuration", "santa.view_configuration")
        response = self.client.get(reverse("santa:pick_rule_certificate", args=(configuration.pk,)),
                                   {"query": self.file_team_id})
        self.assertEqual(response.status_code, 403)

    def test_pick_rule_certificate(self):
        configuration = force_configuration()
        self._login("santa.add_rule")
        response = self.client.get(reverse("santa:pick_rule_certificate", args=(configuration.pk,)),
                                   {"query": self.file_team_id})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/pick_rule_certificate.html")
        certificates = response.context["certificates"]
        self.assertEqual(certificates, [(self.file.signed_by, None)])

    # pick rule team id

    def test_pick_rule_team_id_redirect(self):
        configuration = force_configuration()
        self._login_redirect(reverse("santa:pick_rule_team_id", args=(configuration.pk,)))

    def test_pick_rule_team_id_access_denied(self):
        configuration = force_configuration()
        self._login("santa.add_configuration", "santa.view_configuration")
        response = self.client.get(reverse("santa:pick_rule_team_id", args=(configuration.pk,)),
                                   {"query": self.file_team_id})
        self.assertEqual(response.status_code, 403)

    def test_pick_rule_team_id(self):
        configuration = force_configuration()
        self._login("santa.add_rule")
        response = self.client.get(reverse("santa:pick_rule_team_id", args=(configuration.pk,)),
                                   {"query": self.file_team_id})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/pick_rule_team_id.html")
        team_ids = response.context["team_ids"]
        self.assertEqual(len(team_ids), 1)
        self.assertEqual(team_ids[0][0].organizational_unit, self.file_team_id)

    def test_pick_rule_team_id_special_chars(self):
        configuration = force_configuration()
        self._login("santa.add_rule")
        response = self.client.get(reverse("santa:pick_rule_team_id", args=(configuration.pk,)),
                                   {"query": "[]"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/pick_rule_team_id.html")
        team_ids = response.context["team_ids"]
        self.assertEqual(len(team_ids), 0)

    # pick rule signing id

    def test_pick_rule_signing_id_redirect(self):
        configuration = force_configuration()
        self._login_redirect(reverse("santa:pick_rule_signing_id", args=(configuration.pk,)))

    def test_pick_rule_signing_id_access_denied(self):
        configuration = force_configuration()
        self._login("santa.add_configuration", "santa.view_configuration")
        response = self.client.get(reverse("santa:pick_rule_signing_id", args=(configuration.pk,)),
                                   {"query": self.file_signing_id})
        self.assertEqual(response.status_code, 403)

    def test_pick_rule_signing_id(self):
        configuration = force_configuration()
        self._login("santa.add_rule")
        response = self.client.get(reverse("santa:pick_rule_signing_id", args=(configuration.pk,)),
                                   {"query": self.file_signing_id})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/pick_rule_signing_id.html")
        signing_ids = response.context["signing_ids"]
        self.assertEqual(len(signing_ids), 1)
        self.assertEqual(signing_ids[0][0].signing_id, self.file_signing_id)

    def test_pick_rule_signing_id_special_chars(self):
        configuration = force_configuration()
        self._login("santa.add_rule")
        response = self.client.get(reverse("santa:pick_rule_signing_id", args=(configuration.pk,)),
                                   {"query": "94KV3E626L:Frameworks[]Electron Framework"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/pick_rule_signing_id.html")
        signing_ids = response.context["signing_ids"]
        self.assertEqual(len(signing_ids), 0)

    # terraform export

    def test_terraform_export_redirect(self):
        self._login_redirect(reverse("santa:terraform_export"))

    def test_terraform_export_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:terraform_export"))
        self.assertEqual(response.status_code, 403)

    def test_terraform_export(self):
        self._login("santa.view_configuration", "santa.view_enrollment", "santa.view_rule")
        configuration = force_configuration()
        target = Target.objects.create(type=Target.Type.BINARY, identifier=get_random_string(64, "0123456789abcdef"))
        Rule.objects.create(configuration=configuration, target=target, policy=Rule.Policy.BLOCKLIST)
        response = self.client.get(reverse("santa:terraform_export"))
        self.assertEqual(response.status_code, 200)

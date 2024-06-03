import datetime
from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.test import TestCase, override_settings
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import File
from accounts.models import User
from zentral.contrib.santa.models import Bundle, Configuration, Target
from zentral.core.stores.conf import frontend_store
from .test_rule_engine import new_cdhash, new_sha256, new_team_id


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class SantaSetupViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        # file tree
        cls.cdhash = new_cdhash()
        cls.file_sha256 = new_sha256()
        cls.file_name = get_random_string(12)
        cls.file_bundle_name = get_random_string(12)
        cls.file_cert_sha256 = new_sha256()
        cls.file_team_id = new_team_id()
        cls.file_signing_id = f"{cls.file_team_id}:com.zentral.example"
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
        return Configuration.objects.create(name=get_random_string(12))

    def _force_bundle(self):
        bundle_target = Target.objects.create(type=Target.BUNDLE, identifier=new_sha256())
        return Bundle.objects.create(
            target=bundle_target,
            executable_rel_path=get_random_string(12),
            bundle_id=self.file.bundle.bundle_id,
            name=self.file_bundle_name,
            version=self.file.bundle.bundle_version,
            version_str=self.file.bundle.bundle_version_str,
            binary_count=1
        )

    # targets

    def test_targets_redirect(self):
        self._login_redirect(reverse("santa:targets"))

    def test_targets_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:targets"))
        self.assertEqual(response.status_code, 403)

    def test_targets(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Targets (5)")
        self.assertContains(response, self.cdhash)
        self.assertContains(response, self.file_sha256)
        self.assertContains(response, self.file_cert_sha256)
        self.assertContains(response, self.file_team_id)
        self.assertContains(response, self.file_signing_id)

    def test_binary_targets(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"), {"target_type": Target.BINARY})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Target (1)")
        self.assertNotContains(response, self.cdhash)
        self.assertContains(response, self.file_sha256)
        self.assertNotContains(response, self.file_cert_sha256)
        self.assertContains(response, self.file_team_id)
        self.assertNotContains(response, self.file_signing_id)

    def test_cdhash_targets(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"), {"target_type": Target.CDHASH})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Target (1)")
        self.assertContains(response, self.cdhash)
        self.assertNotContains(response, self.file_sha256)
        self.assertNotContains(response, self.file_cert_sha256)
        self.assertContains(response, self.file_team_id)
        self.assertNotContains(response, self.file_signing_id)

    def test_certificate_targets(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"), {"target_type": Target.CERTIFICATE})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Target (1)")
        self.assertNotContains(response, self.cdhash)
        self.assertNotContains(response, self.file_sha256)
        self.assertContains(response, self.file_cert_sha256)
        self.assertContains(response, self.file_team_id)
        self.assertNotContains(response, self.file_signing_id)

    def test_team_id_targets(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"), {"target_type": Target.TEAM_ID})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Target (1)")
        self.assertNotContains(response, self.cdhash)
        self.assertNotContains(response, self.file_sha256)
        self.assertNotContains(response, self.file_cert_sha256)
        self.assertContains(response, self.file_team_id)
        self.assertNotContains(response, self.file_signing_id)

    def test_signing_id_targets(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"), {"target_type": Target.SIGNING_ID})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Target (1)")
        self.assertNotContains(response, self.cdhash)
        self.assertNotContains(response, self.file_sha256)
        self.assertNotContains(response, self.file_cert_sha256)
        self.assertContains(response, self.file_team_id)
        self.assertContains(response, self.file_signing_id)

    def test_search_targets_empty_results(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"), {"q": "does not exists"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "We didn't find any item related to your search")
        self.assertContains(response, reverse("santa:targets") + '">all the items')

    # binary target

    def test_binary_target_redirect(self):
        self._login_redirect(reverse("santa:binary", args=(self.file_sha256,)))

    def test_binary_target_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:binary", args=(self.file_sha256,)))
        self.assertEqual(response.status_code, 403)

    def test_binary_target_no_configuration(self):
        self._login("santa.view_target", "santa.add_rule")
        response = self.client.get(reverse("santa:binary", args=(self.file_sha256,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_detail.html")
        self.assertContains(response, self.file_sha256)
        self.assertNotContains(response, "createRule")

    def test_binary_target_configuration_no_add_rule_perm(self):
        configuration = self._force_configuration()
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:binary", args=(self.file_sha256,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_detail.html")
        self.assertContains(response, self.file_sha256)
        self.assertNotContains(response, "createRule")
        self.assertNotContains(response, configuration.name)

    def test_binary_target_configuration_add_rule_perm(self):
        configuration = self._force_configuration()
        self._login("santa.view_target", "santa.add_rule")
        response = self.client.get(reverse("santa:binary", args=(self.file_sha256,)))
        self.assertContains(response, "createRule")
        self.assertContains(response, configuration.name)

    def test_binary_target_events_redirect(self):
        self._login_redirect(reverse("santa:binary_events", args=(self.file_sha256,)))

    def test_binary_target_events_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:binary_events", args=(self.file_sha256,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.get_aggregated_object_event_counts")
    def test_binary_target_events(self, get_aggregated_object_event_counts):
        get_aggregated_object_event_counts.return_value = {}
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:binary_events", args=(self.file_sha256,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_events.html")
        self.assertContains(response, self.file_sha256)

    def test_fetch_binary_target_events_redirect(self):
        self._login_redirect(reverse("santa:fetch_binary_events", args=(self.file_sha256,)))

    def test_fetch_binary_target_events_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:fetch_binary_events", args=(self.file_sha256,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.fetch_object_events")
    def test_fetch_binary_target_events(self, fetch_object_events):
        fetch_object_events.return_value = ([], None)
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:fetch_binary_events", args=(self.file_sha256,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/stores/events_events.html")

    def test_binary_target_store_redirect_login_redirect(self):
        self._login_redirect(reverse("santa:binary_events_store_redirect", args=(self.file_sha256,)))

    def test_binary_target_store_redirect_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:binary_events_store_redirect", args=(self.file_sha256,)))
        self.assertEqual(response.status_code, 403)

    def test_binary_target_store_redirect(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:binary_events_store_redirect", args=(self.file_sha256,)),
                                   {"es": frontend_store.name})
        self.assertTrue(response.url.startswith("/kibana/"))

    # bundle target

    def test_bundle_target_redirect(self):
        bundle = self._force_bundle()
        self._login_redirect(reverse("santa:bundle", args=(bundle.target.identifier,)))

    def test_bundle_target_permission_denied(self):
        bundle = self._force_bundle()
        self._login()
        response = self.client.get(reverse("santa:bundle", args=(bundle.target.identifier,)))
        self.assertEqual(response.status_code, 403)

    def test_bundle_target_no_configuration(self):
        bundle = self._force_bundle()
        self._login("santa.view_target", "santa.add_rule")
        response = self.client.get(reverse("santa:bundle", args=(bundle.target.identifier,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_detail.html")
        self.assertContains(response, bundle.target.identifier)
        self.assertNotContains(response, "createRule")

    def test_bundle_target_configuration_no_add_rule_perm(self):
        bundle = self._force_bundle()
        configuration = self._force_configuration()
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:bundle", args=(bundle.target.identifier,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_detail.html")
        self.assertContains(response, bundle.target.identifier)
        self.assertNotContains(response, "createRule")
        self.assertNotContains(response, configuration.name)

    def test_bundle_target_configuration_add_rule_perm(self):
        bundle = self._force_bundle()
        configuration = self._force_configuration()
        self._login("santa.view_target", "santa.add_rule")
        response = self.client.get(reverse("santa:bundle", args=(bundle.target.identifier,)))
        self.assertContains(response, "createRule")
        self.assertContains(response, configuration.name)

    def test_bundle_target_events_permission_denied(self):
        bundle = self._force_bundle()
        self._login()
        response = self.client.get(reverse("santa:bundle_events", args=(bundle.target.identifier,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.get_aggregated_object_event_counts")
    def test_bundle_target_events(self, get_aggregated_object_event_counts):
        get_aggregated_object_event_counts.return_value = {}
        bundle = self._force_bundle()
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:bundle_events", args=(bundle.target.identifier,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_events.html")
        self.assertContains(response, bundle.target.identifier)

    def test_fetch_bundle_target_events_redirect(self):
        bundle = self._force_bundle()
        self._login_redirect(reverse("santa:fetch_bundle_events", args=(bundle.target.identifier,)))

    def test_fetch_bundle_target_events_permission_denied(self):
        bundle = self._force_bundle()
        self._login()
        response = self.client.get(reverse("santa:fetch_bundle_events", args=(bundle.target.identifier,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.fetch_object_events")
    def test_fetch_bundle_target_events(self, fetch_object_events):
        fetch_object_events.return_value = ([], None)
        bundle = self._force_bundle()
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:fetch_bundle_events", args=(bundle.target.identifier,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/stores/events_events.html")

    def test_bundle_target_store_redirect_login_redirect(self):
        bundle = self._force_bundle()
        self._login_redirect(reverse("santa:bundle_events_store_redirect", args=(bundle.target.identifier,)))

    def test_bundle_target_store_redirect_permission_denied(self):
        bundle = self._force_bundle()
        self._login()
        response = self.client.get(reverse("santa:bundle_events_store_redirect", args=(bundle.target.identifier,)))
        self.assertEqual(response.status_code, 403)

    def test_bundle_target_store_redirect(self):
        bundle = self._force_bundle()
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:bundle_events_store_redirect", args=(bundle.target.identifier,)),
                                   {"es": frontend_store.name})
        self.assertTrue(response.url.startswith("/kibana/"))

    # cdhash target

    def test_cdhash_target_redirect(self):
        self._login_redirect(reverse("santa:cdhash", args=(self.cdhash,)))

    def test_cdhash_target_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:cdhash", args=(self.cdhash,)))
        self.assertEqual(response.status_code, 403)

    def test_cdhash_target_no_configuration(self):
        self._login("santa.view_target", "santa.add_rule")
        response = self.client.get(reverse("santa:cdhash", args=(self.cdhash,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_detail.html")
        self.assertContains(response, self.cdhash)
        self.assertNotContains(response, "createRule")

    def test_cdhash_target_configuration_no_add_rule_perm(self):
        configuration = self._force_configuration()
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:cdhash", args=(self.cdhash,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_detail.html")
        self.assertContains(response, self.cdhash)
        self.assertNotContains(response, "createRule")
        self.assertNotContains(response, configuration.name)

    def test_cdhash_target_configuration_add_rule_perm(self):
        configuration = self._force_configuration()
        self._login("santa.view_target", "santa.add_rule")
        response = self.client.get(reverse("santa:cdhash", args=(self.cdhash,)))
        self.assertContains(response, "createRule")
        self.assertContains(response, configuration.name)

    def test_cdhash_target_events_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:cdhash_events", args=(self.cdhash,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.get_aggregated_object_event_counts")
    def test_cdhash_target_events(self, get_aggregated_object_event_counts):
        get_aggregated_object_event_counts.return_value = {}
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:cdhash_events", args=(self.cdhash,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_events.html")
        self.assertContains(response, self.cdhash)

    def test_fetch_cdhash_target_events_redirect(self):
        self._login_redirect(reverse("santa:fetch_cdhash_events", args=(self.cdhash,)))

    def test_fetch_cdhash_target_events_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:fetch_cdhash_events", args=(self.cdhash,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.fetch_object_events")
    def test_fetch_cdhash_target_events(self, fetch_object_events):
        fetch_object_events.return_value = ([], None)
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:fetch_cdhash_events", args=(self.cdhash,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/stores/events_events.html")

    def test_cdhash_target_store_redirect_login_redirect(self):
        self._login_redirect(reverse("santa:cdhash_events_store_redirect", args=(self.cdhash,)))

    def test_cdhash_target_store_redirect_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:cdhash_events_store_redirect", args=(self.cdhash,)))
        self.assertEqual(response.status_code, 403)

    def test_cdhash_target_store_redirect(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:cdhash_events_store_redirect", args=(self.cdhash,)),
                                   {"es": frontend_store.name})
        self.assertTrue(response.url.startswith("/kibana/"))

    # certificate target

    def test_certificate_target_redirect(self):
        self._login_redirect(reverse("santa:certificate", args=(self.file_cert_sha256,)))

    def test_certificate_target_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:certificate", args=(self.file_cert_sha256,)))
        self.assertEqual(response.status_code, 403)

    def test_certificate_target_no_configuration(self):
        self._login("santa.view_target", "santa.add_rule")
        response = self.client.get(reverse("santa:certificate", args=(self.file_cert_sha256,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_detail.html")
        self.assertContains(response, self.file_cert_sha256)
        self.assertNotContains(response, "createRule")

    def test_certificate_target_configuration_no_add_rule_perm(self):
        configuration = self._force_configuration()
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:certificate", args=(self.file_cert_sha256,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_detail.html")
        self.assertContains(response, self.file_cert_sha256)
        self.assertNotContains(response, "createRule")
        self.assertNotContains(response, configuration.name)

    def test_certificate_target_configuration_add_rule_perm(self):
        configuration = self._force_configuration()
        self._login("santa.view_target", "santa.add_rule")
        response = self.client.get(reverse("santa:certificate", args=(self.file_cert_sha256,)))
        self.assertContains(response, "createRule")
        self.assertContains(response, configuration.name)

    def test_certificate_target_events_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:certificate_events", args=(self.file_cert_sha256,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.get_aggregated_object_event_counts")
    def test_certificate_target_events(self, get_aggregated_object_event_counts):
        get_aggregated_object_event_counts.return_value = {}
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:certificate_events", args=(self.file_cert_sha256,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_events.html")
        self.assertContains(response, self.file_cert_sha256)

    def test_fetch_certificate_target_events_redirect(self):
        self._login_redirect(reverse("santa:fetch_certificate_events", args=(self.file_cert_sha256,)))

    def test_fetch_certificate_target_events_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:fetch_certificate_events", args=(self.file_cert_sha256,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.fetch_object_events")
    def test_fetch_certificate_target_events(self, fetch_object_events):
        fetch_object_events.return_value = ([], None)
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:fetch_certificate_events", args=(self.file_cert_sha256,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/stores/events_events.html")

    def test_certificate_target_store_redirect_login_redirect(self):
        self._login_redirect(reverse("santa:certificate_events_store_redirect", args=(self.file_cert_sha256,)))

    def test_certificate_target_store_redirect_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:certificate_events_store_redirect", args=(self.file_cert_sha256,)))
        self.assertEqual(response.status_code, 403)

    def test_certificate_target_store_redirect(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:certificate_events_store_redirect", args=(self.file_cert_sha256,)),
                                   {"es": frontend_store.name})
        self.assertTrue(response.url.startswith("/kibana/"))

    # team ID target

    def test_team_id_target_redirect(self):
        self._login_redirect(reverse("santa:teamid", args=(self.file_team_id,)))

    def test_team_id_target_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:teamid", args=(self.file_team_id,)))
        self.assertEqual(response.status_code, 403)

    def test_team_id_target_no_configuration(self):
        self._login("santa.view_target", "santa.add_rule")
        response = self.client.get(reverse("santa:teamid", args=(self.file_team_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_detail.html")
        self.assertContains(response, self.file_team_id)
        self.assertNotContains(response, "createRule")

    def test_team_id_target_configuration_no_add_rule_perm(self):
        configuration = self._force_configuration()
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:teamid", args=(self.file_team_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_detail.html")
        self.assertContains(response, self.file_team_id)
        self.assertNotContains(response, "createRule")
        self.assertNotContains(response, configuration.name)

    def test_team_id_target_configuration_add_rule_perm(self):
        configuration = self._force_configuration()
        self._login("santa.view_target", "santa.add_rule")
        response = self.client.get(reverse("santa:teamid", args=(self.file_team_id,)))
        self.assertContains(response, "createRule")
        self.assertContains(response, configuration.name)

    def test_team_id_target_events_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:teamid_events", args=(self.file_team_id,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.get_aggregated_object_event_counts")
    def test_team_id_target_events(self, get_aggregated_object_event_counts):
        get_aggregated_object_event_counts.return_value = {}
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:teamid_events", args=(self.file_team_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_events.html")
        self.assertContains(response, self.file_team_id)

    def test_fetch_team_id_target_events_redirect(self):
        self._login_redirect(reverse("santa:fetch_teamid_events", args=(self.file_team_id,)))

    def test_fetch_team_id_target_events_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:fetch_teamid_events", args=(self.file_team_id,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.fetch_object_events")
    def test_fetch_team_id_target_events(self, fetch_object_events):
        fetch_object_events.return_value = ([], None)
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:fetch_teamid_events", args=(self.file_team_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/stores/events_events.html")

    def test_team_id_target_store_redirect_login_redirect(self):
        self._login_redirect(reverse("santa:teamid_events_store_redirect", args=(self.file_team_id,)))

    def test_team_id_target_store_redirect_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:teamid_events_store_redirect", args=(self.file_team_id,)))
        self.assertEqual(response.status_code, 403)

    def test_team_id_target_store_redirect(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:teamid_events_store_redirect", args=(self.file_team_id,)),
                                   {"es": frontend_store.name})
        self.assertTrue(response.url.startswith("/kibana/"))

    # signing ID target

    def test_signing_id_target_redirect(self):
        self._login_redirect(reverse("santa:signingid", args=(self.file_signing_id,)))

    def test_signing_id_target_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:signingid", args=(self.file_signing_id,)))
        self.assertEqual(response.status_code, 403)

    def test_signing_id_target_no_configuration(self):
        self._login("santa.view_target", "santa.add_rule")
        response = self.client.get(reverse("santa:signingid", args=(self.file_signing_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_detail.html")
        self.assertContains(response, self.file_signing_id)
        self.assertNotContains(response, "createRule")

    def test_signing_id_target_configuration_no_add_rule_perm(self):
        configuration = self._force_configuration()
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:signingid", args=(self.file_signing_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_detail.html")
        self.assertContains(response, self.file_signing_id)
        self.assertNotContains(response, "createRule")
        self.assertNotContains(response, configuration.name)

    def test_signing_id_target_configuration_add_rule_perm(self):
        configuration = self._force_configuration()
        self._login("santa.view_target", "santa.add_rule")
        response = self.client.get(reverse("santa:signingid", args=(self.file_signing_id,)))
        self.assertContains(response, "createRule")
        self.assertContains(response, configuration.name)

    def test_signing_id_target_events_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:signingid_events", args=(self.file_signing_id,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.get_aggregated_object_event_counts")
    def test_signing_id_target_events(self, get_aggregated_object_event_counts):
        get_aggregated_object_event_counts.return_value = {}
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:signingid_events", args=(self.file_signing_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_events.html")
        self.assertContains(response, self.file_signing_id)

    def test_fetch_signing_id_target_events_redirect(self):
        self._login_redirect(reverse("santa:fetch_signingid_events", args=(self.file_signing_id,)))

    def test_fetch_signing_id_target_events_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:fetch_signingid_events", args=(self.file_signing_id,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.fetch_object_events")
    def test_fetch_signing_id_target_events(self, fetch_object_events):
        fetch_object_events.return_value = ([], None)
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:fetch_signingid_events", args=(self.file_signing_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/stores/events_events.html")

    def test_signing_id_target_store_redirect_login_redirect(self):
        self._login_redirect(reverse("santa:signingid_events_store_redirect", args=(self.file_signing_id,)))

    def test_signing_id_target_store_redirect_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:signingid_events_store_redirect", args=(self.file_signing_id,)))
        self.assertEqual(response.status_code, 403)

    def test_signing_id_target_store_redirect(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:signingid_events_store_redirect", args=(self.file_signing_id,)),
                                   {"es": frontend_store.name})
        self.assertTrue(response.url.startswith("/kibana/"))

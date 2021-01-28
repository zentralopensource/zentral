import datetime
import json
import plistlib
from django.urls import reverse
from django.test import TestCase, override_settings
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit, File
from accounts.models import User
from zentral.contrib.santa.models import Bundle, Rule, Target


def get_random_sha256():
    return get_random_string(64, "abcdef0123456789")


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class SantaSetupViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.pwd = "godzillapwd"
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", cls.pwd)
        # file tree
        cls.file_sha256 = get_random_sha256()
        cls.file_name = get_random_string()
        cls.file_bundle_name = get_random_string()
        cls.file_cert_sha256 = get_random_sha256()
        cls.file_cert_cn = get_random_string()
        cls.file_cert_ou = get_random_string()
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
                'organizational_unit': cls.file_cert_ou,
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
        cls.file_target = Target.objects.create(type=Target.BINARY, sha256=cls.file_sha256)

    def login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def log_user_in(self):
        response = self.client.post(reverse('login'),
                                    {'username': self.user.username, 'password': self.pwd},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["user"], self.user)

    def log_user_out(self):
        response = self.client.get(reverse('logout'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["user"].is_authenticated, False)

    def post_as_json(self, url_name, data):
        return self.client.post(reverse("santa:{}".format(url_name)),
                                json.dumps(data),
                                content_type="application/json")

    def test_configurations_redirect(self):
        self.login_redirect(reverse("santa:configuration_list"))
        self.login_redirect(reverse("santa:create_configuration"))

    def test_get_create_configuration_view(self):
        self.log_user_in()
        response = self.client.get(reverse("santa:create_configuration"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_form.html")
        self.assertContains(response, "Santa configuration")

    def create_configuration(self):
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
                                     }, follow=True)
        configuration = response.context["object"]
        return response, configuration

    def test_post_create_configuration_view(self):
        self.log_user_in()
        response, configuration = self.create_configuration()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(configuration.enable_sysx_cache, True)
        self.assertEqual(configuration.full_sync_interval, 602)
        self.assertTemplateUsed(response, "santa/configuration_detail.html")
        self.assertContains(response, configuration.name)

    def test_post_update_configuration_view(self):
        self.log_user_in()
        _, configuration = self.create_configuration()
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
                                     }, follow=True)
        self.assertEqual(response.status_code, 200)
        configuration = response.context["object"]
        self.assertEqual(configuration.enable_sysx_cache, False)
        self.assertEqual(configuration.full_sync_interval, 603)
        self.assertTemplateUsed(response, "santa/configuration_detail.html")
        self.assertContains(response, "new lockdown message")

    def test_get_create_enrollment_view(self):
        self.log_user_in()
        _, configuration = self.create_configuration()
        response = self.client.get(reverse("santa:create_enrollment", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/enrollment_form.html")
        self.assertContains(response, "Create enrollment")
        self.assertContains(response, configuration.name)

    def create_enrollment(self, configuration):
        mbu = MetaBusinessUnit.objects.create(name="{} MBU".format(configuration.name))
        mbu.create_enrollment_business_unit()
        response = self.client.post(reverse("santa:create_enrollment", args=(configuration.pk,)),
                                    {"secret-meta_business_unit": mbu.pk,
                                     "configuration": configuration.pk,
                                     "santa_release": ""}, follow=True)
        enrollment = response.context["enrollments"][0]
        self.assertEqual(enrollment.version, 1)
        return response, enrollment

    def test_post_create_enrollment_view(self):
        self.log_user_in()
        _, configuration = self.create_configuration()
        response, enrollment = self.create_enrollment(configuration)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_detail.html")
        self.assertEqual(response.context["object"], configuration)
        # response contains enrollment secret meta business unit name
        self.assertContains(response, enrollment.secret.meta_business_unit.name)
        # response contains link to download enrollment configuration plist
        self.assertContains(response, reverse("santa:enrollment_configuration_plist",
                                              args=(configuration.pk, enrollment.pk)))
        # response contains link to download enrollment configuration profile
        self.assertContains(response, reverse("santa:enrollment_configuration_profile",
                                              args=(configuration.pk, enrollment.pk)))

    def test_enrollment_configuration_view(self):
        self.log_user_in()
        _, configuration = self.create_configuration()
        _, enrollment = self.create_enrollment(configuration)
        self.log_user_out()
        enrollment_configuration_plist_url = reverse(
            "santa:enrollment_configuration_plist", args=(configuration.pk, enrollment.pk)
        )
        self.login_redirect(enrollment_configuration_plist_url)
        enrollment_configuration_profile_url = reverse(
            "santa:enrollment_configuration_profile", args=(configuration.pk, enrollment.pk)
        )
        self.login_redirect(enrollment_configuration_profile_url)
        self.log_user_in()
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
        self.log_user_in()
        _, configuration = self.create_configuration()
        self.log_user_out()
        self.login_redirect(reverse("santa:configuration_rules", args=(configuration.pk,)))
        self.login_redirect(reverse("santa:create_configuration_rule", args=(configuration.pk,)))
        self.login_redirect(reverse("santa:pick_rule_binary", args=(configuration.pk,)))
        self.login_redirect(reverse("santa:pick_rule_bundle", args=(configuration.pk,)))
        self.login_redirect(reverse("santa:pick_rule_certificate", args=(configuration.pk,)))

    def test_create_configuration_rule(self):
        self.log_user_in()
        _, configuration = self.create_configuration()
        # create
        binary_hash = get_random_sha256()
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                    {"target_type": Target.BINARY,
                                     "target_sha256": binary_hash,
                                     "policy": Rule.ALLOWLIST}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_rules.html")
        rule = response.context["object_list"][0]
        self.assertEqual(rule.configuration, configuration)
        self.assertEqual(rule.target.sha256, binary_hash)
        self.assertEqual(rule.target.type, Target.BINARY)
        self.assertEqual(rule.policy, Rule.ALLOWLIST)
        self.assertEqual(rule.custom_msg, "")
        self.assertEqual(rule.serial_numbers, [])
        self.assertEqual(rule.primary_users, [])

    def test_create_conflict_configuration_rule(self):
        self.log_user_in()
        _, configuration = self.create_configuration()
        # create
        binary_hash = get_random_sha256()
        self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                         {"target_type": Target.BINARY,
                          "target_sha256": binary_hash,
                          "policy": Rule.ALLOWLIST}, follow=True)
        # conflict
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                    {"target_type": Target.BINARY,
                                     "target_sha256": binary_hash,
                                     "policy": Rule.BLOCKLIST}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/rule_form.html")
        form = response.context["form"]
        self.assertEqual(form.errors, {'__all__': ['A rule for this target already exists']})

    def test_update_configuration_rule(self):
        self.log_user_in()
        _, configuration = self.create_configuration()
        # create
        binary_hash = get_random_sha256()
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                    {"target_type": Target.BINARY,
                                     "target_sha256": binary_hash,
                                     "policy": Rule.ALLOWLIST}, follow=True)
        rule = response.context["object_list"][0]
        # update
        custom_message = get_random_string()
        serial_numbers = [get_random_string() for i in range(3)]
        primary_users = [get_random_string() for i in range(12)]
        response = self.client.post(reverse("santa:update_configuration_rule", args=(configuration.pk, rule.pk)),
                                    {"target_type": Target.BINARY,
                                     "target_sha256": binary_hash,
                                     "policy": Rule.BLOCKLIST,
                                     "custom_msg": custom_message,
                                     "serial_numbers": ", ".join(serial_numbers),
                                     "primary_users": ",".join(primary_users)}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_rules.html")
        rule = response.context["object_list"][0]
        self.assertEqual(rule.configuration, configuration)
        self.assertEqual(rule.target.sha256, binary_hash)
        self.assertEqual(rule.target.type, Target.BINARY)
        self.assertEqual(rule.policy, Rule.BLOCKLIST)
        self.assertEqual(rule.custom_msg, custom_message)
        self.assertEqual(rule.serial_numbers, serial_numbers)
        self.assertEqual(rule.primary_users, primary_users)

    def test_delete_configuration_rule(self):
        self.log_user_in()
        _, configuration = self.create_configuration()
        # create
        binary_hash = get_random_sha256()
        response = self.client.post(reverse("santa:create_configuration_rule", args=(configuration.pk,)),
                                    {"target_type": Target.BINARY,
                                     "target_sha256": binary_hash,
                                     "policy": Rule.ALLOWLIST}, follow=True)
        rule = response.context["object_list"][0]
        # delete GET
        response = self.client.get(reverse("santa:delete_configuration_rule", args=(configuration.pk, rule.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/rule_confirm_delete.html")
        self.assertContains(response, binary_hash)
        # delete POST
        response = self.client.post(reverse("santa:delete_configuration_rule", args=(configuration.pk, rule.pk)),
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_rules.html")
        self.assertFalse(any(rule.target.sha256 == binary_hash for rule in response.context["object_list"]))

    def test_pick_rule_binary(self):
        self.log_user_in()
        _, configuration = self.create_configuration()
        response = self.client.get(reverse("santa:pick_rule_binary", args=(configuration.pk,)),
                                   {"name": self.file_name})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/pick_rule_binary.html")
        binaries = response.context["binaries"]
        self.assertEqual(binaries, [(self.file, None)])
        self.assertContains(response, self.file.sha_256)

    def test_pick_rule_bundle(self):
        self.log_user_in()
        _, configuration = self.create_configuration()
        bundle_target = Target.objects.create(type=Target.BUNDLE, sha256=get_random_sha256())
        bundle = Bundle.objects.create(
            target=bundle_target,
            path=get_random_string(),
            executable_rel_path=get_random_string(),
            bundle_id=self.file.bundle.bundle_id,
            name=self.file_bundle_name,
            version=self.file.bundle.bundle_version,
            version_str=self.file.bundle.bundle_version_str,
            binary_count=1
        )
        # bundle not ready, no go
        response = self.client.get(reverse("santa:pick_rule_bundle", args=(configuration.pk,)),
                                   {"name": self.file_bundle_name})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/pick_rule_bundle.html")
        self.assertEqual(response.context["bundles"], [(bundle, None)])
        self.assertContains(response, "Bundle not uploaded yet")
        self.assertNotContains(response, "Create rule")
        # bundle read, OK
        bundle.binary_targets.add(self.file_target)
        bundle.uploaded_at = datetime.datetime.now()
        bundle.save()
        response = self.client.get(reverse("santa:pick_rule_bundle", args=(configuration.pk,)),
                                   {"name": self.file_bundle_name})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/pick_rule_bundle.html")
        self.assertEqual(response.context["bundles"], [(bundle, None)])
        self.assertNotContains(response, "Bundle not uploaded yet")
        self.assertContains(response, "Create rule")

    def test_pick_rule_certificate(self):
        self.log_user_in()
        _, configuration = self.create_configuration()
        response = self.client.get(reverse("santa:pick_rule_certificate", args=(configuration.pk,)),
                                   {"query": self.file_cert_ou})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/pick_rule_certificate.html")
        certificates = response.context["certificates"]
        self.assertEqual(certificates, [(self.file.signed_by, None)])

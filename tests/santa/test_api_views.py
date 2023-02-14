import datetime
from functools import reduce
import json
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import get_random_string
from rest_framework import status
import yaml
from accounts.models import User, APIToken
from zentral.conf import settings
from zentral.contrib.inventory.models import Certificate, File, EnrollmentSecret, MetaBusinessUnit, Tag
from zentral.contrib.inventory.serializers import EnrollmentSecretSerializer
from zentral.contrib.santa.events import SantaRuleUpdateEvent
from zentral.contrib.santa.models import Configuration, Rule, RuleSet, Target, Enrollment, Bundle
from zentral.utils.payloads import get_payload_identifier


class APIViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.configuration = Configuration.objects.create(name=get_random_string(256))
        cls.configuration2 = Configuration.objects.create(name=get_random_string(256))
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True
        )
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        cls.api_key = APIToken.objects.update_or_create_for_user(cls.service_account)
        cls.maxDiff = None
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        # file tree
        cls.file_sha256 = get_random_string(64, "abcdef0123456789")
        cls.file_name = get_random_string(12)
        cls.file_bundle_name = get_random_string(12)
        cls.file_cert_sha256 = get_random_string(64, "abcdef0123456789")
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
        cls.file_cert = Certificate.objects.commit({
            "organization": "Awesome Inc",
            "common_name": f"Developer ID Application: Awesome Inc ({cls.file_team_id})",
            "organizational_unit": f"{cls.file_team_id}",
            "sha_256": cls.file_cert_sha256,
            'valid_from': datetime.datetime(2006, 4, 25, 21, 40, 36),
            'valid_until': datetime.datetime(2035, 2, 9, 21, 40, 36),
            'signed_by': {
                'common_name': 'Apple Root CA',
                'organization': 'Apple Inc.',
                'organizational_unit': 'Apple Certification Authority',
                'sha_256': 'b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024',
                'valid_from': datetime.datetime(2006, 4, 25, 21, 40, 36),
                'valid_until': datetime.datetime(2035, 2, 9, 21, 40, 36),
            },
        })

        cls.file_target = Target.objects.create(type=Target.BINARY, identifier=cls.file_sha256)
        cls.file_cert_target = Target.objects.create(type=Target.CERTIFICATE, identifier=cls.file_cert_sha256)
        cls.file_bundle_target = Target.objects.create(type=Target.BUNDLE, identifier=cls.file_sha256)
        cls.file_team_id_target = Target.objects.create(type=Target.TEAM_ID, identifier=cls.file_team_id)

    # utils

    def force_bundle(self, target_identifier=None, fake_upload=False):
        if target_identifier is None:
            target_identifier = get_random_string(length=64, allowed_chars='abcdef0123456789')
        target = Target.objects.create(type=Target.BUNDLE, identifier=target_identifier)
        if fake_upload:
            return Bundle.objects.create(
                target=target,
                binary_count=1,
                uploaded_at=timezone.now().isoformat()
            )
        return Bundle.objects.create(target=target, binary_count=1)

    def force_tags(self, count=6):
        return [Tag.objects.create(name=get_random_string(12)) for _ in range(count)]

    def force_configuration(self):
        return Configuration.objects.create(name=get_random_string(12))

    def force_enrollment(self, tag_count=0):
        configuration = self.force_configuration()
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=self.mbu)
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(tag_count)]
        if tags:
            enrollment_secret.tags.set(tags)
        return (
            Enrollment.objects.create(configuration=configuration, secret=enrollment_secret),
            tags
        )

    def set_permissions(self, *permissions):
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

    def post_data(self, url, data, content_type, include_token=True, dry_run=None):
        kwargs = {"content_type": content_type}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        if dry_run is not None:
            url = f"{url}?{dry_run}"
        return self.client.post(url, data, **kwargs)

    def post_yaml_data(self, url, data, include_token=True):
        content_type = "application/yaml"
        data = yaml.dump(data)
        return self.post_data(url, data, content_type, include_token)

    def get(self, url, data=None, include_token=True):
        kwargs = {}
        if data is not None:
            kwargs["data"] = data
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.get(url, **kwargs)

    def delete(self, url, include_token=True):
        kwargs = {}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.delete(url, **kwargs)

    def put_data(self, url, data, content_type, include_token=True):
        kwargs = {"content_type": content_type}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.put(url, data, **kwargs)

    def put_json_data(self, url, data, include_token=True):
        content_type = "application/json"
        data = json.dumps(data)
        return self.put_data(url, data, content_type, include_token)

    def post_json_data(self, url, data, include_token=True, dry_run=None):
        content_type = "application/json"
        data = json.dumps(data)
        return self.post_data(url, data, content_type, include_token, dry_run)

    def force_rule(self, target_type="BINARY", policy=Rule.ALLOWLIST, target_identifier=None, configuration=None,
                   bundle=False, force_tags=False):
        if target_identifier is None:
            target_identifier = get_random_string(length=64, allowed_chars='abcdef0123456789')
        if configuration is None:
            configuration = self.configuration
        if bundle:
            target_type = Target.BUNDLE
            self.force_bundle(target_identifier=target_identifier, fake_upload=True)
        target, _ = Target.objects.get_or_create(type=target_type, identifier=target_identifier)
        rule = Rule.objects.create(
            target=target,
            policy=policy,
            configuration=configuration,
            custom_msg="custom msg",
            description="description",
            primary_users=["yolo@example.com"]
        )
        if force_tags:
            tags = self.force_tags(1)
            excluded_tags = self.force_tags(1)
            if tags:
                rule.tags.set(tags)
            if excluded_tags:
                rule.excluded_tags.set(excluded_tags)
            return rule, tags, excluded_tags
        return rule

    # ingest file info

    def test_ingest_fileinfo_unauthorized(self):
        url = reverse("santa_api:ingest_file_info")
        response = self.post_json_data(url, [], include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_ingest_fileinfo_permission_denied(self):
        url = reverse("santa_api:ingest_file_info")
        response = self.post_json_data(url, [], include_token=True)
        self.assertEqual(response.status_code, 403)

    def test_ruleset_update_unauthorized(self):
        url = reverse("santa_api:ruleset_update")
        response = self.post_json_data(url, {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_ruleset_update_permission_denied(self):
        url = reverse("santa_api:ruleset_update")
        response = self.post_json_data(url, {}, include_token=True)
        self.assertEqual(response.status_code, 403)

    def test_ingest_fileinfo(self):
        self.set_permissions("inventory.add_file")
        url = reverse("santa_api:ingest_file_info")
        data = [
            {'Bundle Name': '1Password 7',
             'Bundle Version': '70700015',
             'Bundle Version Str': '7.7',
             'Code-signed': 'Yes',
             'Path': '/Applications/1Password 7.app/Contents/MacOS/1Password 7',
             'Rule': 'Allowed (Unknown)',
             'SHA-1': '98f07121d283e305812798d42bd29da8ece10abe',
             'SHA-256': 'df469b87ae9221e5df3f0e585f05926865cef907d332934dc33a3fa4b6b2cc3a',
             'Signing Chain': [
                 {'Common Name': 'Developer ID Application: AgileBits Inc. (2BUA8C4S2C)',
                  'Organization': 'AgileBits Inc.',
                  'Organizational Unit': '2BUA8C4S2C',
                  'SHA-1': '2d0637d09a7ae4cf11668971b11ce56bfb56c5bc',
                  'SHA-256': '137868ff9b2caf3f640e71c847cd7fb870de6620c2dcc3a90287cf5a4a511940',
                  'Valid From': '2017/02/19 00:39:36 +0100',
                  'Valid Until': '2022/02/20 00:39:36 +0100'},
                 {'Common Name': 'Developer ID Certification Authority',
                  'Organization': 'Apple Inc.',
                  'Organizational Unit': 'Apple Certification Authority',
                  'SHA-1': '3b166c3b7dc4b751c9fe2afab9135641e388e186',
                  'SHA-256': '7afc9d01a62f03a2de9637936d4afe68090d2de18d03f29c88cfb0b1ba63587f',
                  'Valid From': '2012/02/01 23:12:15 +0100',
                  'Valid Until': '2027/02/01 23:12:15 +0100'},
                 {'Common Name': 'Apple Root CA',
                  'Organization': 'Apple Inc.',
                  'Organizational Unit': 'Apple Certification Authority',
                  'SHA-1': '611e5b662c593a08ff58d14ae22452d198df6c60',
                  'SHA-256': 'b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024',
                  'Valid From': '2006/04/25 23:40:36 +0200',
                  'Valid Until': '2035/02/09 22:40:36 +0100'}],
             'Type': 'Executable (x86_64)'},
            {'Type': 'YOLO'},
        ]
        file_qs = File.objects.filter(sha_256=data[0]['SHA-256'])
        cert_qs = Certificate.objects.filter(sha_256=data[0]['Signing Chain'][0]['SHA-256'])
        self.assertEqual(file_qs.count(), 0)
        self.assertEqual(cert_qs.count(), 0)
        response = self.post_json_data(url, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response,
            {'added': 1,
             'db_errors': 0,
             'deserialization_errors': 0,
             'ignored': 1,
             'present': 0}
        )
        response = self.post_json_data(url, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response,
            {'added': 0,
             'db_errors': 0,
             'deserialization_errors': 0,
             'ignored': 1,
             'present': 1}
        )
        self.assertEqual(file_qs.count(), 1)
        self.assertEqual(cert_qs.count(), 1)

    def test_ruleset_update_rule(self):
        self.set_permissions("santa.add_ruleset", "santa.change_ruleset",
                             "santa.add_rule", "santa.change_rule", "santa.delete_rule")
        url = reverse("santa_api:ruleset_update")

        # JSON rule for all configurations
        data = {
            "name": get_random_string(12),
            "rules": [
                {"rule_type": "BINARY",
                 "identifier": get_random_string(64, "0123456789abcdef"),
                 "policy": "BLOCKLIST",
                 "description": "Description",
                 "primary_users": [get_random_string(32)],
                 "excluded_primary_users": [get_random_string(32)],
                 "serial_numbers": [get_random_string(32)],
                 "excluded_serial_numbers": [get_random_string(32)],
                 "tags": [get_random_string(32)],
                 "excluded_tags": [get_random_string(32)]}
            ]
        }
        first_result_configurations = [
            {'name': self.configuration.name,
             'pk': self.configuration.pk,
             'rule_results': {'created': 1,
                              'deleted': 0,
                              'present': 0,
                              'updated': 0}},
            {'name': self.configuration2.name,
             'pk': self.configuration2.pk,
             'rule_results': {'created': 1,
                              'deleted': 0,
                              'present': 0,
                              'updated': 0}}
        ]
        self.assertEqual(self.configuration.rule_set.count(), 0)
        self.assertEqual(self.configuration2.rule_set.count(), 0)
        # dryRun, nothing changes
        response = self.post_json_data(url, data, dry_run="dryRun")
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertTrue(json_response["dry_run"])
        self.assertEqual(json_response["result"], "created")
        self.assertEqual(json_response["configurations"], first_result_configurations)
        self.assertEqual(RuleSet.objects.filter(name=data["name"]).count(), 0)
        self.assertEqual(self.configuration.rule_set.count(), 0)
        self.assertEqual(self.configuration2.rule_set.count(), 0)
        # dryRun=All, nothing changes
        response = self.post_json_data(url, data, dry_run="dryRun=All")
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertTrue(json_response["dry_run"])
        # real fire and water run
        response = self.post_json_data(url, data, dry_run="yolo")
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        ruleset = RuleSet.objects.get(name=data["name"])
        self.assertEqual(
            json_response,
            {'ruleset': {
                 'name': ruleset.name,
                 'pk': ruleset.pk
             },
             'dry_run': False,
             'result': 'created',
             'configurations': first_result_configurations}
        )
        self.assertEqual(self.configuration.rule_set.count(), 1)
        self.assertEqual(self.configuration2.rule_set.count(), 1)
        self.assertEqual(
            self.configuration.rule_set.filter(
                target__type=Target.BINARY,
                target__identifier=data["rules"][0]["identifier"],
                policy=Rule.BLOCKLIST,
                description="Description",
                serial_numbers=data["rules"][0]["serial_numbers"],
                excluded_serial_numbers=data["rules"][0]["excluded_serial_numbers"],
                primary_users=data["rules"][0]["primary_users"],
                excluded_primary_users=data["rules"][0]["excluded_primary_users"],
                tags__name=data["rules"][0]["tags"][0],
                excluded_tags__name=data["rules"][0]["excluded_tags"][0],
                custom_msg="",
                ruleset=ruleset,
            ).count(), 1
        )
        self.assertEqual(
            self.configuration2.rule_set.filter(
                target__type=Target.BINARY,
                target__identifier=data["rules"][0]["identifier"],
                policy=Rule.BLOCKLIST,
                description="Description",
                serial_numbers=data["rules"][0]["serial_numbers"],
                excluded_serial_numbers=data["rules"][0]["excluded_serial_numbers"],
                primary_users=data["rules"][0]["primary_users"],
                excluded_primary_users=data["rules"][0]["excluded_primary_users"],
                tags__name=data["rules"][0]["tags"][0],
                excluded_tags__name=data["rules"][0]["excluded_tags"][0],
                custom_msg="",
                ruleset=ruleset,
            ).count(), 1
        )
        self.assertEqual(self.configuration2.rule_set.count(), 1)

        # idempotent / YAML
        response = self.post_yaml_data(url, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response,
            {'ruleset': {
                'name': ruleset.name,
                'pk': ruleset.pk
              },
             'dry_run': False,
             'result': 'present',
             'configurations': [
                {'name': self.configuration.name,
                 'pk': self.configuration.pk,
                 'rule_results': {'created': 0,
                                  'deleted': 0,
                                  'present': 1,
                                  'updated': 0}},
                {'name': self.configuration2.name,
                 'pk': self.configuration2.pk,
                 'rule_results': {'created': 0,
                                  'deleted': 0,
                                  'present': 1,
                                  'updated': 0}}]}
        )
        self.assertEqual(self.configuration.rule_set.count(), 1)
        self.assertEqual(self.configuration2.rule_set.count(), 1)

        # update
        data["rules"][0]["custom_msg"] = get_random_string(12)
        data["rules"][0]["description"] = get_random_string(12)
        data["rules"][0]["serial_numbers"].append(get_random_string(12))
        data["rules"][0]["excluded_serial_numbers"].append(get_random_string(12))
        data["rules"][0]["primary_users"] = [get_random_string(12)]
        data["rules"][0]["excluded_primary_users"].append(get_random_string(12))
        data["rules"][0]["tags"].insert(0, get_random_string(12))
        data["rules"][0]["excluded_tags"] = [get_random_string(12)]
        response = self.post_json_data(url, data)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        ruleset = RuleSet.objects.get(name=data["name"])
        self.assertEqual(
            json_response,
            {'ruleset': {
                'name': ruleset.name,
                'pk': ruleset.pk
             },
             'dry_run': False,
             'result': 'present',
             'configurations': [
                {'name': self.configuration.name,
                 'pk': self.configuration.pk,
                 'rule_results': {'created': 0,
                                  'deleted': 0,
                                  'present': 0,
                                  'updated': 1}},
                {'name': self.configuration2.name,
                 'pk': self.configuration2.pk,
                 'rule_results': {'created': 0,
                                  'deleted': 0,
                                  'present': 0,
                                  'updated': 1}}]}
        )
        self.assertEqual(self.configuration.rule_set.count(), 1)
        self.assertEqual(self.configuration2.rule_set.count(), 1)
        self.assertEqual(
            self.configuration.rule_set.filter(
                target__type=Target.BINARY,
                target__identifier=data["rules"][0]["identifier"],
                policy=Rule.BLOCKLIST,
                serial_numbers__overlap=data["rules"][0]["serial_numbers"],
                serial_numbers__len=len(data["rules"][0]["serial_numbers"]),
                excluded_serial_numbers__overlap=data["rules"][0]["excluded_serial_numbers"],
                excluded_serial_numbers__len=len(data["rules"][0]["excluded_serial_numbers"]),
                primary_users__overlap=data["rules"][0]["primary_users"],
                primary_users__len=len(data["rules"][0]["primary_users"]),
                excluded_primary_users__overlap=data["rules"][0]["excluded_primary_users"],
                excluded_primary_users__len=len(data["rules"][0]["excluded_primary_users"]),
                tags__name=data["rules"][0]["tags"][0],
                excluded_tags__name=data["rules"][0]["excluded_tags"][0],
                custom_msg=data["rules"][0]["custom_msg"],
                description=data["rules"][0]["description"],
                ruleset=ruleset,
            ).count(), 1
        )
        self.assertEqual(
            self.configuration2.rule_set.filter(
                target__type=Target.BINARY,
                target__identifier=data["rules"][0]["identifier"],
                policy=Rule.BLOCKLIST,
                serial_numbers__overlap=data["rules"][0]["serial_numbers"],
                serial_numbers__len=len(data["rules"][0]["serial_numbers"]),
                excluded_serial_numbers__overlap=data["rules"][0]["excluded_serial_numbers"],
                excluded_serial_numbers__len=len(data["rules"][0]["excluded_serial_numbers"]),
                primary_users__overlap=data["rules"][0]["primary_users"],
                primary_users__len=len(data["rules"][0]["primary_users"]),
                excluded_primary_users__overlap=data["rules"][0]["excluded_primary_users"],
                excluded_primary_users__len=len(data["rules"][0]["excluded_primary_users"]),
                tags__name=data["rules"][0]["tags"][0],
                excluded_tags__name=data["rules"][0]["excluded_tags"][0],
                custom_msg=data["rules"][0]["custom_msg"],
                description=data["rules"][0]["description"],
                ruleset=ruleset,
            ).count(), 1
        )

        # scoped + conflict
        data2 = {
            "name": get_random_string(12),
            "configurations": [self.configuration.name],
            "rules": [
                {"rule_type": "BINARY",
                 "identifier": data["rules"][0]["identifier"],
                 "policy": "ALLOWLIST"}
            ]
        }
        response = self.post_json_data(url, data2)
        self.assertEqual(response.status_code, 400)
        json_response = response.json()
        self.assertEqual(
            json_response,
            {"rules": {"0": {"non_field_errors": [f'BINARY/{data["rules"][0]["identifier"]}: conflict']}}}
        )
        self.assertEqual(self.configuration.rule_set.count(), 1)
        self.assertEqual(self.configuration2.rule_set.count(), 1)
        self.assertEqual(RuleSet.objects.filter(name=data2["name"]).count(), 0)

        # new scoped ruleset
        data2["rules"][0]["identifier"] = get_random_string(64, "0123456789abcdef")
        response = self.post_json_data(url, data2)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        ruleset2 = RuleSet.objects.get(name=data2["name"])
        self.assertEqual(
            json_response,
            {'ruleset': {
                'name': ruleset2.name,
                'pk': ruleset2.pk
             },
             'dry_run': False,
             'result': 'created',
             'configurations': [
                {'name': self.configuration.name,
                 'pk': self.configuration.pk,
                 'rule_results': {'created': 1,
                                  'deleted': 0,
                                  'present': 0,
                                  'updated': 0}}]}
        )
        self.assertEqual(self.configuration.rule_set.count(), 2)
        self.assertEqual(self.configuration2.rule_set.count(), 1)
        self.assertEqual(
            self.configuration.rule_set.filter(
                target__type=Target.BINARY,
                target__identifier=data2["rules"][0]["identifier"],
                policy=Rule.ALLOWLIST,
                ruleset=ruleset2,
            ).count(), 1
        )

        # delete last rule / YAML
        data2["rules"] = []
        response = self.post_json_data(url, data2)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response,
            {'ruleset': {
                'name': ruleset2.name,
                'pk': ruleset2.pk
             },
             'dry_run': False,
             'result': 'present',
             'configurations': [
                {'name': self.configuration.name,
                 'pk': self.configuration.pk,
                 'rule_results': {'created': 0,
                                  'deleted': 1,
                                  'present': 0,
                                  'updated': 0}}]}
        )
        self.assertEqual(self.configuration.rule_set.count(), 1)
        self.assertEqual(self.configuration2.rule_set.count(), 1)

        # duplicated
        sha256 = get_random_string(64, "0123456789abcdef")
        response = self.post_json_data(
            url,
            {"name": get_random_string(12),
             "rules": [
                 {"rule_type": "BINARY", "identifier": sha256, "policy": "ALLOWLIST"},
                 {"rule_type": "BINARY", "identifier": sha256, "policy": "ALLOWLIST"},
             ]}
        )
        self.assertEqual(response.status_code, 400)
        json_response = response.json()
        self.assertEqual(
            json_response,
            {"rules": {"1": {"non_field_errors": [f'BINARY/{sha256}: duplicated']}}}
        )

        # unknown bundle
        sha256 = get_random_string(64, "0123456789abcdef")
        response = self.post_json_data(
            url,
            {"name": get_random_string(12),
             "rules": [
                 {"rule_type": "BUNDLE", "identifier": sha256, "policy": "ALLOWLIST"},
             ]}
        )
        self.assertEqual(response.status_code, 400)
        json_response = response.json()
        self.assertEqual(
            json_response,
            {"rules": {"0": {"non_field_errors": [f'BUNDLE/{sha256}: bundle unknown or not uploaded']}}}
        )

        # serial number conflict
        response = self.post_json_data(
            url,
            {"name": get_random_string(12),
             "rules": [{"rule_type": "BINARY",
                        "identifier": get_random_string(64, "0123456789abcdef"),
                        "policy": "ALLOWLIST",
                        "serial_numbers": ["01234567", "12345678"],
                        "excluded_serial_numbers": ["12345678"]}]}
        )
        self.assertEqual(response.status_code, 400)
        json_response = response.json()
        self.assertEqual(
            json_response,
            {"rules": {"0": {"non_field_errors": ["Conflict between serial_numbers and excluded_serial_numbers"]}}}
        )

        # primary user conflict
        response = self.post_json_data(
            url,
            {"name": get_random_string(12),
             "rules": [{"rule_type": "BINARY",
                        "identifier": get_random_string(64, "0123456789abcdef"),
                        "policy": "ALLOWLIST",
                        "primary_users": ["vincent", "françois"],
                        "excluded_primary_users": ["françois", "paul", "les autres…"]}]}
        )
        self.assertEqual(response.status_code, 400)
        json_response = response.json()
        self.assertEqual(
            json_response,
            {"rules": {"0": {"non_field_errors": ["Conflict between primary_users and excluded_primary_users"]}}}
        )

        # tag conflict
        response = self.post_json_data(
            url,
            {"name": get_random_string(12),
             "rules": [{"rule_type": "BINARY",
                        "identifier": get_random_string(64, "0123456789abcdef"),
                        "policy": "ALLOWLIST",
                        "tags": ["vincent", "françois"],
                        "excluded_tags": ["françois", "paul", "les autres…"]}]}
        )
        self.assertEqual(response.status_code, 400)
        json_response = response.json()
        self.assertEqual(
            json_response,
            {"rules": {"0": {"non_field_errors": ["Conflict between tags and excluded_tags"]}}}
        )

    # targets export

    def test_targets_export_unauthorized(self):
        response = self.client.post(reverse("santa_api:targets_export"))
        self.assertEqual(response.status_code, 401)

    def test_targets_export_permission_denied(self):
        response = self.client.post(reverse("santa_api:targets_export"),
                                    HTTP_AUTHORIZATION=f"Token {self.api_key}")
        self.assertEqual(response.status_code, 403)

    def test_targets_export(self):
        self.set_permissions("santa.view_target")
        response = self.client.post(reverse("santa_api:targets_export"),
                                    HTTP_AUTHORIZATION=f"Token {self.api_key}")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("task_id", response.data)
        self.assertIn("task_result_url", response.data)

    def test_team_id_targets_export(self):
        self.set_permissions("santa.view_target")
        response = self.client.post("{}?target_type=TEAMID".format(reverse("santa_api:targets_export")),
                                    HTTP_AUTHORIZATION=f"Token {self.api_key}")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("task_id", response.data)
        self.assertIn("task_result_url", response.data)

    # rules

    def test_rule_list_unauthorized(self):
        response = self.client.get(reverse("santa_api:rules"))
        self.assertEqual(response.status_code, 401)

    def test_rule_list_permission_denied(self):
        response = self.client.get(reverse("santa_api:rules"),
                                   HTTP_AUTHORIZATION=f"Token {self.api_key}")
        self.assertEqual(response.status_code, 403)

    def test_rule_list_put_method_not_allowed(self):
        self.set_permissions("santa.change_rule")
        response = self.client.put(reverse("santa_api:rules"),
                                   HTTP_AUTHORIZATION=f"Token {self.api_key}")
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_rule_list_delete_method_not_allowed(self):
        self.set_permissions("santa.delete_rule")
        response = self.client.delete(reverse("santa_api:rules"),
                                      HTTP_AUTHORIZATION=f"Token {self.api_key}")
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_rule_list(self):
        self.set_permissions("santa.view_rule")
        rule = self.force_rule()
        self.force_rule(target_type=Target.CERTIFICATE, configuration=self.configuration2)
        response = self.client.get(reverse("santa_api:rules"),
                                   HTTP_AUTHORIZATION=f"Token {self.api_key}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        rules = response.json()
        rules.sort(key=lambda r: r["id"])
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0]["target_type"], "BINARY")
        self.assertEqual(rules[0]["target_identifier"], rule.target.identifier)
        self.assertEqual(rules[0]["configuration"], self.configuration.pk)
        self.assertEqual(rules[0]["primary_users"], ["yolo@example.com"])

    def test_rule_list_by_type(self):
        self.set_permissions("santa.view_rule")
        self.force_rule()
        rule2 = self.force_rule(target_type=Target.CERTIFICATE, configuration=self.configuration2)
        response = self.client.get(reverse("santa_api:rules"),
                                   data={"target_type": "CERTIFICATE"},
                                   HTTP_AUTHORIZATION=f"Token {self.api_key}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        rules = response.json()
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["id"], rule2.pk)

    def test_rule_list_by_unknown_type(self):
        self.set_permissions("santa.view_rule")
        self.force_rule()
        self.force_rule(target_type=Target.CERTIFICATE, configuration=self.configuration2)
        response = self.client.get(reverse("santa_api:rules"),
                                   data={"target_type": "YOLO"},
                                   HTTP_AUTHORIZATION=f"Token {self.api_key}")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.json(),
            {'target_type': ['Select a valid choice. YOLO is not one of the available choices.']}
        )

    def test_rule_list_by_identifier(self):
        self.set_permissions("santa.view_rule")
        self.force_rule()
        rule2 = self.force_rule(target_type=Target.CERTIFICATE, configuration=self.configuration2)
        response = self.client.get(reverse("santa_api:rules"),
                                   data={"target_identifier": rule2.target.identifier},
                                   HTTP_AUTHORIZATION=f"Token {self.api_key}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        rules = response.json()
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["id"], rule2.pk)

    def test_rule_list_by_configuration(self):
        self.set_permissions("santa.view_rule")
        self.force_rule()
        rule2 = self.force_rule(target_type=Target.CERTIFICATE, configuration=self.configuration2)
        response = self.client.get(reverse("santa_api:rules"),
                                   data={"configuration_id": self.configuration2.pk},
                                   HTTP_AUTHORIZATION=f"Token {self.api_key}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        rules = response.json()
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["id"], rule2.pk)

    def test_rule_list_by_unknown_configuration(self):
        self.set_permissions("santa.view_rule")
        self.force_rule()
        self.force_rule(target_type=Target.CERTIFICATE, configuration=self.configuration2)
        response = self.client.get(reverse("santa_api:rules"),
                                   data={"configuration_id": 12832398912},
                                   HTTP_AUTHORIZATION=f"Token {self.api_key}")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.json(),
            {'configuration_id': ['Select a valid choice. That choice is not one of the available choices.']}
        )

    # rules create

    def test_create_rule_that_exist_failed(self):
        configuration = self.force_configuration()
        rule = self.force_rule(configuration=configuration)
        self.set_permissions("santa.add_rule")
        data = {
            "configuration": configuration.pk,
            "policy": rule.policy,
            "target_type": rule.target.type,
            "target_identifier": rule.target.identifier
        }
        response = self.post_json_data(reverse("santa_api:rules"), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(), {'target': ['rule already exists for this target']})
        self.assertEqual(Rule.objects.count(), 1)

    def test_create_rule_team_id_failed(self):
        self.set_permissions("santa.add_rule")
        data = {
            "configuration": self.configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": Target.TEAM_ID,
            "target_identifier": get_random_string(32)
        }
        response = self.post_json_data(reverse("santa_api:rules"), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(), {'target_identifier': ['Invalid Team ID']})
        self.assertEqual(Rule.objects.count(), 0)

    def test_create_rule_sha256_error(self):
        self.set_permissions("santa.add_rule")
        data = {
            "configuration": self.configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": Target.BINARY,
            "target_identifier": get_random_string(5)
        }
        response = self.post_json_data(reverse("santa_api:rules"), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(), {'target_identifier': ['Invalid sha256']})
        self.assertEqual(Rule.objects.count(), 0)

    def test_create_rule_bundle_does_not_exist(self):
        self.set_permissions("santa.add_rule")
        data = {
            "configuration": self.configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": Target.BUNDLE,
            "target_identifier": get_random_string(length=64, allowed_chars='abcdef0123456789')
        }
        response = self.post_json_data(reverse("santa_api:rules"), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(),
                         {'target_type': [f'Bundle for {data["target_identifier"]} does not exist.']})
        self.assertEqual(Rule.objects.count(), 0)

    def test_create_rule_with_bundle_not_uploaded(self):
        target_identifier = get_random_string(length=64, allowed_chars='abcdef0123456789')
        self.force_bundle(target_identifier=target_identifier)
        self.set_permissions("santa.add_rule")
        data = {
            "configuration": self.configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": Target.BUNDLE,
            "target_identifier": target_identifier
        }
        response = self.post_json_data(reverse("santa_api:rules"), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(), {'bundle': ['This bundle has not been uploaded yet.']})
        self.assertEqual(Rule.objects.count(), 0)

    def test_create_rule_with_target_bundle(self):
        target_identifier = get_random_string(length=64, allowed_chars='abcdef0123456789')
        self.force_bundle(target_identifier=target_identifier, fake_upload=True)
        self.set_permissions("santa.add_rule")
        data = {
            "configuration": self.configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": Target.BUNDLE,
            "target_identifier": target_identifier
        }
        response = self.post_json_data(reverse("santa_api:rules"), data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Rule.objects.count(), 1)
        rule = Rule.objects.select_related('target').first()
        self.assertEqual(rule.target.type, Target.BUNDLE)
        self.assertEqual(rule.target.identifier, target_identifier)

    def test_create_rule_policy_custom_msg_error(self):
        self.set_permissions("santa.add_rule")
        data = {
            "configuration": self.configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": Target.BINARY,
            "target_identifier": get_random_string(length=64, allowed_chars='abcdef0123456789'),
            "custom_msg": "This should not be here"
        }
        response = self.post_json_data(reverse("santa_api:rules"), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(), {'custom_msg': [f'Can only be set on BLOCKLIST rules']})
        self.assertEqual(Rule.objects.count(), 0)

    def test_create_rule_bundle_not_bundle_policy_error(self):
        target_identifier = get_random_string(length=64, allowed_chars='abcdef0123456789')
        self.force_bundle(target_identifier=target_identifier, fake_upload=True)
        self.set_permissions("santa.add_rule")
        data = {
            "configuration": self.configuration.pk,
            "policy": Rule.BLOCKLIST,
            "target_type": Target.BUNDLE,
            "target_identifier": target_identifier
        }
        response = self.post_json_data(reverse("santa_api:rules"), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(), {'policy': [f'Policy {Rule.BLOCKLIST} not allowed for bundles.']})
        self.assertEqual(Rule.objects.count(), 0)

    def test_create_rule_primary_user_conflicts_error(self):
        primary_user_conflicts = f"{get_random_string(5)}@@corp.com"
        self.set_permissions("santa.add_rule")
        data = {
            "configuration": self.configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": Target.BINARY,
            "target_identifier": get_random_string(length=64, allowed_chars='abcdef0123456789'),
            "primary_users": [primary_user_conflicts],
            "excluded_primary_users": [primary_user_conflicts]
        }
        response = self.post_json_data(reverse("santa_api:rules"), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(),
                         {'primary_users': [f"'{primary_user_conflicts}' in both included and excluded"]})
        self.assertEqual(Rule.objects.count(), 0)

    def test_create_rule_serial_number_conflicts_error(self):
        serial_number_conflicts = get_random_string(32)
        self.set_permissions("santa.add_rule")
        data = {
            "configuration": self.configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": Target.BINARY,
            "target_identifier": get_random_string(length=64, allowed_chars='abcdef0123456789'),
            "serial_numbers": [serial_number_conflicts],
            "excluded_serial_numbers": [serial_number_conflicts]
        }
        response = self.post_json_data(reverse("santa_api:rules"), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(),
                         {'serial_numbers': [f"'{serial_number_conflicts}' in both included and excluded"]})
        self.assertEqual(Rule.objects.count(), 0)

    def test_create_rule_tag_conflicts_error(self):
        tag_conflicts = self.force_tags(1)
        self.set_permissions("santa.add_rule")
        data = {
            "configuration": self.configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": Target.BINARY,
            "target_identifier": get_random_string(length=64, allowed_chars='abcdef0123456789'),
            "tags": [t.id for t in tag_conflicts],
            "excluded_tags": [t.id for t in tag_conflicts]
        }
        response = self.post_json_data(reverse("santa_api:rules"), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(),
                         {'tags': [f"'{[t.name for t in tag_conflicts][0]}' in both included and excluded"]})
        self.assertEqual(Rule.objects.count(), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_rule_create(self, post_event):
        configuration = self.force_configuration()
        self.set_permissions("santa.add_rule")
        data = {
            "configuration": configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": Target.BINARY,
            "target_identifier": get_random_string(length=64, allowed_chars='abcdef0123456789'),
            "description": "Description",
            "primary_users": [get_random_string(12)],
            "excluded_primary_users": [get_random_string(12)],
            "serial_numbers": [get_random_string(12)],
            "excluded_serial_numbers": [get_random_string(12)],
            "tags": [t.id for t in self.force_tags(1)],
            "excluded_tags": [t.id for t in self.force_tags(1)],
        }
        with self.captureOnCommitCallbacks(execute=True):
            response = self.post_json_data(reverse("santa_api:rules"), data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        rule = Rule.objects.select_related('target').first()
        self.assertEqual(Rule.objects.count(), 1)
        self.assertEqual(response.json(), {
            "id": rule.id,
            "configuration": configuration.pk,
            "policy": 1,
            "target_type": Target.BINARY,
            "target_identifier": data["target_identifier"],
            "description": "Description",
            "custom_msg": '',
            "ruleset": None,
            "primary_users": data["primary_users"],
            "excluded_primary_users": data["excluded_primary_users"],
            "serial_numbers": data["serial_numbers"],
            "excluded_serial_numbers": data["excluded_serial_numbers"],
            "tags": data["tags"],
            "excluded_tags": data["excluded_tags"],
            "created_at": rule.created_at.isoformat(),
            "updated_at": rule.updated_at.isoformat(),
            "version": 1
        })
        self.assertEqual(response.json(), {
            "id": rule.pk,
            "configuration": configuration.pk,
            "policy": rule.policy,
            "target_type": rule.target.type,
            "target_identifier": rule.target.identifier,
            "description": rule.description,
            "primary_users": rule.primary_users,
            "ruleset": None,
            "custom_msg": '',
            "excluded_primary_users": rule.excluded_primary_users,
            "serial_numbers": rule.serial_numbers,
            "excluded_serial_numbers": rule.excluded_serial_numbers,
            "tags": [t.pk for t in rule.tags.all()],
            "excluded_tags": [t.pk for t in rule.excluded_tags.all()],
            "created_at": rule.created_at.isoformat(),
            "updated_at": rule.updated_at.isoformat(),
            "version": rule.version
        })
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 1)
        self.assertIsInstance(events[0], SantaRuleUpdateEvent)
        self.assertEqual(events[0].payload, {
            'rule': {
                'configuration': {
                    'pk': configuration.pk,
                    'name': configuration.name,
                },
                'target': {
                    'type': 'BINARY',
                    'sha256': rule.target.identifier,
                },
                'policy': 'ALLOWLIST',
                'serial_numbers': data['serial_numbers'],
                'excluded_serial_numbers': data['excluded_serial_numbers'],
                'primary_users': data['primary_users'],
                'excluded_primary_users': data['excluded_primary_users'],
                'tags': [{'pk': t.pk, 'name': t.name} for t in rule.tags.all()],
                'excluded_tags': [{'pk': t.pk, 'name': t.name} for t in rule.excluded_tags.all()]},
            'result': 'created'
        })

    def test_rule_create_with_policy_error(self):
        configuration = self.force_configuration()
        self.set_permissions("santa.add_rule")
        data = {
            "configuration": configuration.pk,
            "policy": "invalid",
            "target_type": Target.BINARY,
            "target_identifier": get_random_string(length=64, allowed_chars='abcdef0123456789')
        }
        response = self.post_json_data(reverse("santa_api:rules"), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(), {'policy': ['"invalid" is not a valid choice.']})
        self.assertEqual(Rule.objects.count(), 0)

    def test_rule_create_with_custom_msg(self):
        configuration = self.force_configuration()
        self.set_permissions("santa.add_rule")
        data = {
            "configuration": configuration.pk,
            "policy": Rule.BLOCKLIST,
            "target_type": Target.TEAM_ID,
            "target_identifier": "1234567890",
            "custom_msg": "Custom message"
        }
        response = self.post_json_data(reverse("santa_api:rules"), data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Rule.objects.count(), 1)
        self.assertEqual(response.json()["custom_msg"], "Custom message")
        rule = Rule.objects.first()
        self.assertEqual(rule.custom_msg, "Custom message")

    def test_rule_create_unauthorized(self):
        response = self.client.post(reverse("santa_api:rules"))
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_rule_create_permission_denied(self):
        response = self.client.post(reverse("santa_api:rules"), HTTP_AUTHORIZATION=f"Token {self.api_key}")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # rules update

    def test_update_rule_existing(self):
        configuration = self.force_configuration()
        rule = self.force_rule(configuration=configuration)
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": rule.target.type,
            "target_identifier": rule.target.identifier,
            "description": "Description Text Updated"
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["description"], "Description Text Updated")
        rule.refresh_from_db()
        self.assertEqual(rule.description, "Description Text Updated")
        self.assertEqual(rule.version, 1)

    def test_update_rule_change_tags(self):
        tags = [t.id for t in self.force_tags(3)]
        configuration = self.force_configuration()
        rule = self.force_rule(configuration=configuration)
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": rule.target.type,
            "target_identifier": rule.target.identifier,
            "tags": tags
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(set(response.json()["tags"]), set(tags))
        rule.refresh_from_db()
        self.assertEqual(set([t.id for t in rule.tags.all()]), set(tags))
        self.assertEqual(rule.version, 1)

    def test_update_rule_change_excluded_tags(self):
        tags = [t.id for t in self.force_tags(3)]
        configuration = self.force_configuration()
        rule = self.force_rule(configuration=configuration)
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": rule.target.type,
            "target_identifier": rule.target.identifier,
            "excluded_tags": tags
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(set(response.json()["excluded_tags"]), set(tags))
        rule.refresh_from_db()
        self.assertEqual(set([t.id for t in rule.excluded_tags.all()]), set(tags))
        self.assertEqual(rule.version, 1)

    def test_update_rule_change_description(self):
        configuration = self.force_configuration()
        rule = self.force_rule(configuration=configuration)
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": rule.target.type,
            "target_identifier": rule.target.identifier,
            "description": "I was added recently"
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["description"], "I was added recently")
        rule.refresh_from_db()
        self.assertEqual(rule.description, "I was added recently")
        self.assertEqual(rule.version, 1)

    def test_update_rule_change_excluded_primary_users(self):
        users = [f"{get_random_string(5)}@@corp.com" for _ in range(5)]
        configuration = self.force_configuration()
        rule = self.force_rule(configuration=configuration)
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": rule.target.type,
            "target_identifier": rule.target.identifier,
            "excluded_primary_users": users
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(set(response.json()["excluded_primary_users"]), set(users))
        rule.refresh_from_db()
        self.assertEqual(set([u for u in rule.excluded_primary_users]), set(users))
        self.assertEqual(rule.version, 1)

    def test_update_rule_change_primary_users_and_excluded_primary_users(self):
        users = [f"{get_random_string(5)}@@corp.com" for _ in range(5)]
        users2 = [f"{get_random_string(5)}@@corp.com" for _ in range(3)]
        configuration = self.force_configuration()
        rule = self.force_rule(configuration=configuration)
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": rule.target.type,
            "target_identifier": rule.target.identifier,
            "primary_users": users,
            "excluded_primary_users": users2
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(set(response.json()["primary_users"]), set(users))
        self.assertEqual(set(response.json()["excluded_primary_users"]), set(users2))
        rule.refresh_from_db()
        self.assertEqual(set([u for u in rule.primary_users]), set(users))
        self.assertEqual(set([u for u in rule.excluded_primary_users]), set(users2))
        self.assertEqual(rule.version, 1)

    def test_update_rule_change_primary_users(self):
        users = [f"{get_random_string(5)}@@corp.com" for _ in range(5)]
        configuration = self.force_configuration()
        rule = self.force_rule(configuration=configuration)
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": rule.target.type,
            "target_identifier": rule.target.identifier,
            "primary_users": users
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(set(response.json()["primary_users"]), set(users))
        rule.refresh_from_db()
        self.assertEqual(set([u for u in rule.primary_users]), set(users))
        self.assertEqual(rule.version, 1)

    def test_update_rule_change_target_identifier(self):
        configuration = self.force_configuration()
        rule = self.force_rule(configuration=configuration)
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": rule.target.type,
            "target_identifier": get_random_string(length=64, allowed_chars='abcdef0123456789')
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["target_identifier"], data["target_identifier"])
        rule.refresh_from_db()
        self.assertEqual(rule.target.identifier, data["target_identifier"])
        self.assertEqual(rule.version, 1)

    def test_update_rule_change_target_type_and_target_identifier(self):
        configuration = self.force_configuration()
        rule = self.force_rule(configuration=configuration)
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": Target.TEAM_ID,
            "target_identifier": '1234567890'
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["target_type"], Target.TEAM_ID)
        self.assertEqual(response.json()["target_identifier"], '1234567890')
        rule.refresh_from_db()
        self.assertEqual(rule.target.type, Target.TEAM_ID)
        self.assertEqual(rule.target.identifier, '1234567890')
        self.assertEqual(rule.version, 1)

    def test_update_rule_change_config(self):
        configuration = self.force_configuration()
        configuration2 = self.force_configuration()
        rule = self.force_rule(configuration=configuration)
        self.assertEqual(rule.version, 1)
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration2.pk,
            "policy": rule.policy,
            "target_type": rule.target.type,
            "target_identifier": rule.target.identifier,
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["configuration"], configuration2.pk)
        rule.refresh_from_db()
        self.assertEqual(rule.configuration.pk, configuration2.pk)
        self.assertEqual(rule.version, 1)

    def test_update_rule_target_exists_error(self):
        target_identifier = get_random_string(length=64, allowed_chars='abcdef0123456789')
        configuration = self.force_configuration()
        configuration2 = self.force_configuration()
        rule = self.force_rule(configuration=configuration, target_identifier=target_identifier,
                               target_type=Target.BINARY)
        rule2 = self.force_rule(configuration=configuration2, target_identifier=target_identifier,
                                target_type=Target.BINARY)
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration2.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": rule2.target.type,
            "target_identifier": rule2.target.identifier,
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(), {"target": ["rule already exists for this target"]})
        rule.refresh_from_db()
        self.assertEqual(rule.version, 1)

    def test_update_rule_team_id_error(self):
        configuration = self.force_configuration()
        target_identifier = "1234567890"
        rule = self.force_rule(configuration=configuration, target_identifier=target_identifier,
                               target_type=Target.TEAM_ID)
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration.pk,
            "policy": rule.policy,
            "target_type": rule.target.type,
            "target_identifier": get_random_string(32)
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(), {'target_identifier': ['Invalid Team ID']})
        rule.refresh_from_db()
        self.assertEqual(rule.target.identifier, target_identifier)
        self.assertEqual(rule.version, 1)

    def test_update_rule_sha256_error(self):
        configuration = self.force_configuration()
        target_identifier = get_random_string(length=64, allowed_chars='abcdef0123456789')
        rule = self.force_rule(configuration=configuration, target_identifier=target_identifier)
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": Target.BINARY,
            "target_identifier": get_random_string(5)
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(), {'target_identifier': ['Invalid sha256']})
        rule.refresh_from_db()
        self.assertEqual(rule.target.identifier, target_identifier)
        self.assertEqual(rule.version, 1)

    def test_update_rule_bundle_not_exist_error(self):
        target_identifier = get_random_string(length=64, allowed_chars='abcdef0123456789')
        configuration = self.force_configuration()
        rule = self.force_rule(configuration=configuration, target_identifier=target_identifier,
                               target_type=Target.BUNDLE)
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": Target.BUNDLE,
            "target_identifier": target_identifier
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(),
                         {'target_type': [f'Bundle for {data["target_identifier"]} does not exist.']})
        rule.refresh_from_db()
        self.assertEqual(rule.version, 1)

    def test_update_rule_bundle_not_uploaded_error(self):
        target_identifier = get_random_string(length=64, allowed_chars='abcdef0123456789')
        configuration = self.force_configuration()
        rule = self.force_rule(configuration=configuration, target_identifier=target_identifier)
        self.force_bundle(target_identifier=target_identifier)
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": Target.BUNDLE,
            "target_identifier": target_identifier
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(), {'bundle': ['This bundle has not been uploaded yet.']})
        rule.refresh_from_db()
        self.assertEqual(rule.version, 1)

    def test_update_rule_bundle_change_to_new_bundle(self):
        bundle_target_identifier1 = get_random_string(length=64, allowed_chars='abcdef0123456789')
        bundle_target_identifier2 = get_random_string(length=64, allowed_chars='abcdef0123456789')
        configuration = self.force_configuration()
        rule = self.force_rule(configuration=configuration, target_identifier=bundle_target_identifier1, bundle=True)
        new_bundle = self.force_bundle(target_identifier=bundle_target_identifier2, fake_upload=True)
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration.pk,
            "policy": rule.policy,
            "target_type": rule.target.type,
            "target_identifier": bundle_target_identifier2
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["target_identifier"], bundle_target_identifier2)
        rule.refresh_from_db()
        self.assertEqual(rule.target.identifier, bundle_target_identifier2)
        self.assertEqual(rule.version, 1)

    def test_update_rule_policy_custom_msg_error(self):
        configuration = self.force_configuration()
        target_identifier = get_random_string(length=64, allowed_chars='abcdef0123456789')
        rule = self.force_rule(configuration=configuration, target_identifier=target_identifier,
                               policy=Rule.BLOCKLIST)
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": Target.BINARY,
            "target_identifier": target_identifier,
            "custom_msg": "This should not be here"
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(), {'custom_msg': [f'Can only be set on BLOCKLIST rules']})
        rule.refresh_from_db()
        self.assertNotEqual(rule.custom_msg, "This should not be here")
        self.assertEqual(rule.policy, Rule.BLOCKLIST)
        self.assertEqual(rule.version, 1)

    def test_update_change_version_readonly(self):
        configuration = self.force_configuration()
        rule = self.force_rule(configuration=configuration)
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration.pk,
            "policy": rule.policy,
            "target_type": rule.target.type,
            "target_identifier": rule.target.identifier,
            "version": 95
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        rule.refresh_from_db()
        self.assertEqual(rule.version, 1)

    def test_update_change_ruleset_readonly(self):
        ruleset = RuleSet.objects.create(name="Test")
        configuration = self.force_configuration()
        rule = self.force_rule(configuration=configuration)
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration.pk,
            "policy": rule.policy,
            "target_type": rule.target.type,
            "target_identifier": rule.target.identifier,
            "ruleset": ruleset.pk
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        rule.refresh_from_db()
        self.assertEqual(rule.ruleset, None)
        self.assertEqual(rule.version, 1)

    def test_update_rule_bundle_not_bundle_policy_error(self):
        target_identifier = get_random_string(length=64, allowed_chars='abcdef0123456789')
        configuration = self.force_configuration()
        rule = self.force_rule(configuration=configuration, target_identifier=target_identifier)
        bundle = self.force_bundle(target_identifier=target_identifier, fake_upload=True)
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration.pk,
            "policy": Rule.BLOCKLIST,
            "target_type": Target.BUNDLE,
            "target_identifier": target_identifier
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(), {'policy': [f'Policy {Rule.BLOCKLIST} not allowed for bundles.']})
        rule.refresh_from_db()
        self.assertEqual(rule.policy, Rule.ALLOWLIST)
        self.assertEqual(rule.target.type, Target.BINARY)
        self.assertEqual(rule.version, 1)

    def test_update_rule_primary_user_conflicts_error(self):
        configuration = self.force_configuration()
        target_identifier = get_random_string(length=64, allowed_chars='abcdef0123456789')
        rule = self.force_rule(configuration=configuration, target_identifier=target_identifier)
        primary_user_conflicts = f"{get_random_string(5)}@@corp.com"
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": Target.BINARY,
            "target_identifier": target_identifier,
            "primary_users": [primary_user_conflicts],
            "excluded_primary_users": [primary_user_conflicts]
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(),
                         {'primary_users': [f"'{primary_user_conflicts}' in both included and excluded"]})
        rule.refresh_from_db()
        self.assertEqual(rule.primary_users, ['yolo@example.com'])
        self.assertEqual(rule.excluded_primary_users, [])
        self.assertEqual(rule.version, 1)

    def test_update_rule_serial_number_conflicts_error(self):
        configuration = self.force_configuration()
        target_identifier = get_random_string(length=64, allowed_chars='abcdef0123456789')
        rule = self.force_rule(configuration=configuration, target_identifier=target_identifier)
        serial_number_conflicts = get_random_string(32)
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": self.configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": Target.BINARY,
            "target_identifier": target_identifier,
            "serial_numbers": [serial_number_conflicts],
            "excluded_serial_numbers": [serial_number_conflicts]
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(),
                         {'serial_numbers': [f"'{serial_number_conflicts}' in both included and excluded"]})
        rule.refresh_from_db()
        self.assertEqual(rule.serial_numbers, [])
        self.assertEqual(rule.excluded_serial_numbers, [])
        self.assertEqual(rule.version, 1)

    def test_update_rule_tag_conflicts_error(self):
        configuration = self.force_configuration()
        target_identifier = get_random_string(length=64, allowed_chars='abcdef0123456789')
        rule = self.force_rule(configuration=configuration, target_identifier=target_identifier)
        tag_conflicts = self.force_tags(1)
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": Target.BINARY,
            "target_identifier": target_identifier,
            "tags": [t.id for t in tag_conflicts],
            "excluded_tags": [t.id for t in tag_conflicts]
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(),
                         {'tags': [f"'{[t.name for t in tag_conflicts][0]}' in both included and excluded"]})
        rule.refresh_from_db()
        self.assertEqual(rule.tags.count(), 0)
        self.assertEqual(rule.excluded_tags.count(), 0)
        self.assertEqual(rule.version, 1)

    def test_update_rule_target_does_not_exist(self):
        configuration = self.force_configuration()
        target_identifier = get_random_string(length=64, allowed_chars='abcdef0123456789')
        rule = self.force_rule(configuration=configuration)
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration.pk,
            "policy": Rule.ALLOWLIST,
            "target_type": Target.BINARY,
            "target_identifier": target_identifier
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        rule.refresh_from_db()
        self.assertEqual(rule.target.identifier, target_identifier)
        self.assertEqual(rule.version, 1)

    def test_update_rule_change_custom_msg(self):
        configuration = self.force_configuration()
        rule = self.force_rule(configuration=configuration, target_type=Target.BINARY, policy=Rule.BLOCKLIST)
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration.pk,
            "policy": rule.policy,
            "target_type": rule.target.type,
            "target_identifier": rule.target.identifier,
            "description": rule.description,
            "custom_msg": "new custom message"
        }
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        rule.refresh_from_db()
        self.assertEqual(rule.custom_msg, "new custom message")
        self.assertEqual(rule.version, 2)

    def test_update_rule_not_found(self):
        self.set_permissions("santa.change_rule")
        response = self.put_json_data(reverse("santa_api:rule", args=(1234567890,)), {})
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_update_rule_permission_denied(self):
        configuration = self.force_configuration()
        rule = self.force_rule(configuration=configuration)
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), {})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_update_rule_unauthorized(self):
        configuration = self.force_configuration()
        rule = self.force_rule(configuration=configuration)
        response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), {}, include_token=False)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_rule(self, post_event):
        configuration = self.force_configuration()
        configuration2 = self.force_configuration()
        rule, initial_tags, initial_excluded_tags = self.force_rule(configuration=configuration, force_tags=True)
        target_identifier = rule.target.identifier
        self.set_permissions("santa.change_rule")
        data = {
            "configuration": configuration2.pk,
            "policy": Rule.BLOCKLIST,
            "target_type": Target.TEAM_ID,
            "target_identifier": "0123456789",
            "description": "new description",
            "custom_msg": "new custom block message",
            "serial_numbers": [get_random_string(12)],
            "excluded_serial_numbers": [get_random_string(12)],
            "primary_users": [get_random_string(12)],
            "excluded_primary_users": [get_random_string(12)],
            "tags": [t.id for t in self.force_tags(1)]
        }
        with self.captureOnCommitCallbacks(execute=True):
            response = self.put_json_data(reverse("santa_api:rule", args=(rule.pk,)), data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        rule = Rule.objects.select_related('target').first()
        self.assertEqual(response.json(), {
            "id": rule.id,
            "configuration": configuration2.pk,
            "policy": Rule.BLOCKLIST,
            "target_type": Target.TEAM_ID,
            "target_identifier": data["target_identifier"],
            "description": "new description",
            "custom_msg": "new custom block message",
            "ruleset": None,
            "primary_users": data["primary_users"],
            "excluded_primary_users": data["excluded_primary_users"],
            "serial_numbers": data["serial_numbers"],
            "excluded_serial_numbers": data["excluded_serial_numbers"],
            "tags": data["tags"],
            "excluded_tags": [t.pk for t in initial_excluded_tags],
            "created_at": rule.created_at.isoformat(),
            "updated_at": rule.updated_at.isoformat(),
            "version": 2
        })
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 1)
        self.assertIsInstance(events[0], SantaRuleUpdateEvent)
        self.assertEqual(events[0].payload, {
            'rule': {
                'configuration': {
                    'pk': configuration2.pk,
                    'name': configuration2.name,
                },
                'target': {
                    'type': 'TEAMID',
                    'team_id': '0123456789'
                },
                'policy': 'BLOCKLIST',
                'custom_msg': 'new custom block message',
                'serial_numbers': rule.serial_numbers,
                'excluded_serial_numbers': rule.excluded_serial_numbers,
                'primary_users': rule.primary_users,
                'excluded_primary_users': rule.excluded_primary_users,
                'tags': [{'pk': t.pk, 'name': t.name} for t in rule.tags.all()],
                'excluded_tags': [{'pk': t.pk, 'name': t.name} for t in initial_excluded_tags],
            },
            'result': 'updated',
            'updates': {
                'removed': {
                    'policy': 'ALLOWLIST',
                    'custom_msg': 'custom msg',
                    'description': 'description',
                    'primary_users': ['yolo@example.com'],
                    'configuration': {
                        'pk': configuration.pk,
                        'name': configuration.name
                    },
                    'tags': [{'pk': t.pk, 'name': t.name} for t in initial_tags],
                    'target': {
                        'type': 'BINARY',
                        'sha256': target_identifier
                    }
                },
                'added': {
                    'policy': 'BLOCKLIST',
                    'custom_msg': 'new custom block message',
                    'description': 'new description',
                    'serial_numbers': data['serial_numbers'],
                    'excluded_serial_numbers': data['excluded_serial_numbers'],
                    'primary_users': data['primary_users'],
                    'excluded_primary_users': data['excluded_primary_users'],
                    'configuration': {
                        'pk': configuration2.pk,
                        'name': configuration2.name
                    },
                    'tags': [{'pk': t.pk, 'name': t.name} for t in rule.tags.all()],
                    'target': {
                        'type': 'TEAMID',
                        'team_id': '0123456789'
                    }
                }
            }
        })

    # rule delete

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_rule_delete(self, post_event):
        configuration = self.force_configuration()
        target_identifier = get_random_string(length=64, allowed_chars='abcdef0123456789')
        rule = self.force_rule(configuration=configuration, target_identifier=target_identifier)
        self.set_permissions("santa.delete_rule")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.delete(reverse("santa_api:rule", args=(rule.pk,)))
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(Rule.objects.count(), 0)
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 1)
        self.assertIsInstance(events[0], SantaRuleUpdateEvent)
        self.assertEqual(events[0].payload, {
            'rule': {
                'configuration': {
                    'pk': configuration.pk,
                    'name': configuration.name
                }, 'target': {
                    'type': 'BINARY',
                    'sha256': rule.target.identifier
                }, 'policy': 'ALLOWLIST',
                'custom_msg': 'custom msg',
                'primary_users': ['yolo@example.com']},
            'result': 'deleted'
        })

    def test_rule_delete_not_found(self):
        self.set_permissions("santa.delete_rule")
        response = self.delete(reverse("santa_api:rule", args=(123456789,)))
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.json(), {'detail': 'Not found.'})

    def test_rule_delete_unauthorized(self):
        configuration = self.force_configuration()
        rule = self.force_rule(configuration=configuration)
        response = self.delete(reverse("santa_api:rule", args=(rule.pk,)), include_token=False)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_rule_delete_permission_denied(self):
        configuration = self.force_configuration()
        rule = self.force_rule(configuration=configuration)
        response = self.delete(reverse("santa_api:rule", args=(rule.pk,)))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # list configuration

    def test_get_configurations_unauthorized(self):
        response = self.get(reverse("santa_api:configurations"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_configurations_permission_denied(self):
        response = self.get(reverse("santa_api:configurations"))
        self.assertEqual(response.status_code, 403)

    def test_get_configurations(self):
        config = self.force_configuration()
        self.set_permissions("santa.view_configuration")
        response = self.get(reverse('santa_api:configurations'), data={"name": config.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data,
                         [{"id": config.pk,
                           "name": config.name,
                           'client_mode': 1,
                           "client_certificate_auth": False,
                           "batch_size": 50,
                           "full_sync_interval": 600,
                           "enable_bundles": False,
                           "enable_transitive_rules": False,
                           "allowed_path_regex": '',
                           "blocked_path_regex": '',
                           "block_usb_mount": False,
                           "remount_usb_mode": [],
                           "allow_unknown_shard": 100,
                           "enable_all_event_upload_shard": 0,
                           "sync_incident_severity": 0,
                           "created_at": config.created_at.isoformat(),
                           "updated_at": config.updated_at.isoformat()
                           }])

    # get configuration

    def test_get_configuration_unauthorized(self):
        configuration = self.force_configuration()
        response = self.get(reverse("santa_api:configuration", args=(configuration.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_configuration_permission_denied(self):
        configuration = self.force_configuration()
        response = self.get(reverse("santa_api:configuration", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_configuration(self):
        config = self.force_configuration()
        self.set_permissions("santa.view_configuration")
        response = self.get(reverse('santa_api:configuration', args=(config.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(
            response.json(),
            {"id": config.pk,
             "name": config.name,
             'client_mode': 1,
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
             "created_at": config.created_at.isoformat(),
             "updated_at": config.updated_at.isoformat()}
        )

    # create configuration

    def test_create_configuration(self):
        self.set_permissions("santa.add_configuration")
        data = {'name': 'Configuration0'}
        response = self.post_json_data(reverse('santa_api:configurations'), data)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(Configuration.objects.filter(name='Configuration0').count(), 1)
        configuration = Configuration.objects.get(name="Configuration0")
        self.assertEqual(configuration.name, 'Configuration0')

    def test_create_configuration_unauthorized(self):
        data = {'name': 'Configuration0'}
        self.set_permissions("santa.configurations")
        response = self.post_json_data(reverse('santa_api:configurations'), data, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_configuration_permission_denied(self):
        data = {'name': 'Configuration0'}
        response = self.post_json_data(reverse('santa_api:configurations'), data)
        self.assertEqual(response.status_code, 403)

    # update configuration

    def test_update_configuration_unauthorized(self):
        config = self.force_configuration()
        data = {'name': get_random_string(12)}
        self.set_permissions("santa.change_configuration")
        response = self.put_json_data(
            reverse("santa_api:configuration", args=(config.pk,)),
            data, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_configuration_permission_denied(self):
        config = self.force_configuration()
        data = {'name': get_random_string(12)}
        response = self.put_json_data(
            reverse("santa_api:configuration", args=(config.pk,)),
            data)
        self.assertEqual(response.status_code, 403)

    def test_update_configuration(self):
        config = self.force_configuration()
        new_name = get_random_string(12)
        data = {'name': new_name}
        self.set_permissions("santa.change_configuration")
        response = self.put_json_data(reverse('santa_api:configuration', args=(config.pk,)), data)
        self.assertEqual(response.status_code, 200)
        config.refresh_from_db()
        self.assertEqual(config.name, new_name)

    def test_update_configuration_name_exists(self):
        config0 = self.force_configuration()
        config1 = self.force_configuration()
        data = {'name': config0.name}
        self.set_permissions("santa.change_configuration")
        response = self.put_json_data(reverse('santa_api:configuration', args=(config1.pk,)), data)
        self.assertEqual(response.status_code, 400)
        response_j = response.json()
        self.assertEqual(response_j["name"][0], "configuration with this name already exists.")

    # delete configuration

    def test_delete_configuration_unauthorized(self):
        config = self.force_configuration()
        self.set_permissions("santa.delete_configuration")
        response = self.delete(reverse("santa_api:configuration", args=(config.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_configuration_permission_denied(self):
        config = self.force_configuration()
        response = self.delete(reverse("santa_api:configuration", args=(config.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_configuration(self):
        config = self.force_configuration()
        self.set_permissions("santa.delete_configuration")
        response = self.delete(reverse('santa_api:configuration', args=(config.pk,)))
        self.assertEqual(response.status_code, 204)

    def test_delete_configuration_error(self):
        config = self.force_configuration()
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=self.mbu)
        Enrollment.objects.create(configuration=config, secret=enrollment_secret)
        self.set_permissions("santa.delete_configuration")
        response = self.delete(reverse('santa_api:configuration', args=(config.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ["This configuration cannot be deleted"])

    # list enrollments

    def test_get_enrollments_unauthorized(self):
        self.set_permissions("santa.view_enrollments")
        response = self.get(reverse("santa_api:enrollments"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollments_permission_denied(self):
        response = self.get(reverse("santa_api:enrollments"))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollments(self):
        enrollment, tags = self.force_enrollment(tag_count=1)
        self.set_permissions("santa.view_enrollment")
        response = self.get(reverse('santa_api:enrollments'))
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            {'id': enrollment.pk,
             'configuration': enrollment.configuration.pk,
             'enrolled_machines_count': 0,
             'secret': {
                 'id': enrollment.secret.pk,
                 'secret': enrollment.secret.secret,
                 'meta_business_unit': self.mbu.pk,
                 'tags': [tags[0].pk],
                 'serial_numbers': None,
                 'udids': None,
                 'quota': None,
                 'request_count': 0
             },
             'version': 1,
             "configuration_profile_download_url":
                 f'https://{settings["api"]["fqdn"]}'
                 f'{reverse("santa_api:enrollment_configuration_profile", args=(enrollment.pk,))}',
             "plist_download_url": f'https://{settings["api"]["fqdn"]}'
                                   f'{reverse("santa_api:enrollment_plist", args=(enrollment.pk,))}',
             'created_at': enrollment.created_at.isoformat(),
             'updated_at': enrollment.updated_at.isoformat()},
            response.json()
        )

    # filter enrollments

    def test_get_enrollments_search(self):
        enrollment1, _ = self.force_enrollment()
        enrollment2, _ = self.force_enrollment()
        enrollment3, _ = self.force_enrollment()
        self.set_permissions("santa.view_enrollment")
        response = self.get(reverse('santa_api:enrollments'), {'configuration_id': enrollment2.configuration.pk})
        self.assertEqual(response.status_code, 200)
        for enrollment in response.json():
            self.assertNotEqual(enrollment['configuration'], enrollment1.configuration.pk)
            self.assertEqual(enrollment['configuration'], enrollment2.configuration.pk)
            self.assertNotEqual(enrollment['configuration'], enrollment3.configuration.pk)

    def test_get_enrollments_search_bad_request(self):
        for i in range(3):
            self.force_enrollment()
        self.set_permissions("santa.view_enrollment")
        response = self.get(reverse('santa_api:enrollments'), {'configuration_id': 4})
        self.assertEqual(response.status_code, 400)

    def test_get_enrollments_search_unauthorized(self):
        enrollment, _ = self.force_enrollment()
        self.set_permissions("santa.view_enrollment")
        response = self.get(reverse('santa_api:enrollments'), {'configuration_id': enrollment.configuration.pk},
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollments_search_permission_denied(self):
        enrollment, _ = self.force_enrollment()
        response = self.get(reverse('santa_api:enrollments'), {'configuration_id': enrollment.configuration.pk})
        self.assertEqual(response.status_code, 403)

    # get enrollment

    def test_get_enrollment_unauthorized(self):
        enrollment, _ = self.force_enrollment()
        self.set_permissions("santa.view_enrollment")
        response = self.get(reverse("santa_api:enrollment", args=(enrollment.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollment_permission_denied(self):
        enrollment, _ = self.force_enrollment()
        response = self.get(reverse("santa_api:enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_not_found(self):
        self.set_permissions("santa.view_enrollment")
        response = self.get(reverse("santa_api:enrollment", args=(1213028133,)))
        self.assertEqual(response.status_code, 404)

    def test_get_enrollment(self):
        enrollment, _ = self.force_enrollment()
        self.set_permissions("santa.view_enrollment")
        response = self.get(reverse('santa_api:enrollment', args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'id': enrollment.pk,
             'configuration': enrollment.configuration.pk,
             'enrolled_machines_count': 0,
             'secret': {
                 'id': enrollment.secret.pk,
                 'secret': enrollment.secret.secret,
                 'meta_business_unit': self.mbu.pk,
                 'tags': [],
                 'serial_numbers': None,
                 'udids': None,
                 'quota': None,
                 'request_count': 0
             },
             'version': 1,
             "configuration_profile_download_url":
                 f'https://{settings["api"]["fqdn"]}'
                 f'{reverse("santa_api:enrollment_configuration_profile", args=(enrollment.pk,))}',
             "plist_download_url": f'https://{settings["api"]["fqdn"]}'
                                   f'{reverse("santa_api:enrollment_plist", args=(enrollment.pk,))}',
             'created_at': enrollment.created_at.isoformat(),
             'updated_at': enrollment.updated_at.isoformat()},
        )

    # get enrollment configuration

    def test_get_enrollment_plist_unauthorized(self):
        enrollment, _ = self.force_enrollment()
        self.set_permissions("santa.view_enrollment")
        response = self.get(reverse("santa_api:enrollment_plist", args=(enrollment.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollment_plist_permission_denied(self):
        enrollment, _ = self.force_enrollment()
        response = self.get(reverse("santa_api:enrollment_plist", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_plist_not_found(self):
        self.set_permissions("santa.view_enrollment")
        response = self.get(reverse("santa_api:enrollment_plist", args=(1213028133,)))
        self.assertEqual(response.status_code, 404)

    def test_get_enrollment_plist(self):
        enrollment, _ = self.force_enrollment()
        self.set_permissions("santa.view_enrollment")
        response = self.get(reverse('santa_api:enrollment_plist', args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/x-plist')
        self.assertEqual(response['Content-Disposition'],
                         f'attachment; filename="zentral_santa_configuration.enrollment_{enrollment.pk}.plist"')
        self.assertEqual(int(response['Content-Length']), len(response.content))

    def test_get_enrollment_configuration_profile_unauthorized(self):
        enrollment, _ = self.force_enrollment()
        self.set_permissions("santa.view_enrollment")
        response = self.get(reverse("santa_api:enrollment_configuration_profile", args=(enrollment.pk,)),
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollment_configuration_profile_permission_denied(self):
        enrollment, _ = self.force_enrollment()
        response = self.get(reverse("santa_api:enrollment_configuration_profile", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_configuration_profile_not_found(self):
        self.set_permissions("santa.view_enrollment")
        response = self.get(reverse("santa_api:enrollment_configuration_profile", args=(1213028133,)))
        self.assertEqual(response.status_code, 404)

    def test_get_enrollment_configuration_profile(self):
        identifier = get_payload_identifier("santa_configuration")
        enrollment, _ = self.force_enrollment()
        self.set_permissions("santa.view_enrollment")
        response = self.get(reverse('santa_api:enrollment_configuration_profile', args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/octet-stream')
        self.assertEqual(response['Content-Disposition'], f'attachment; filename="{identifier}.mobileconfig"')
        self.assertEqual(int(response['Content-Length']), len(response.content))

    # create enrollment

    def test_create_enrollment(self):
        config = self.force_configuration()
        self.set_permissions("santa.add_enrollment")
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(2)]
        response = self.post_json_data(
            reverse('santa_api:enrollments'),
            {'configuration': config.pk,
             'secret': {"meta_business_unit": self.mbu.pk,
                        "tags": [t.id for t in tags]}}
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(Enrollment.objects.filter(configuration__name=config.name).count(), 1)
        enrollment = Enrollment.objects.get(configuration__name=config.name)
        self.assertEqual(enrollment.secret.meta_business_unit, self.mbu)
        self.assertEqual(
            set(enrollment.secret.tags.all()),
            set(tags)
        )

    def test_create_enrollment_unauthorized(self):
        data = {'name': 'Configuration0'}
        self.set_permissions("santa.add_enrollments")
        response = self.post_json_data(reverse('santa_api:enrollments'), data, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_enrollment_permission_denied(self):
        data = {'name': 'Configuration0'}
        response = self.post_json_data(reverse('santa_api:enrollments'), data)
        self.assertEqual(response.status_code, 403)

    # update enrollment

    def test_update_enrollment(self):
        enrollment, _ = self.force_enrollment(tag_count=2)
        enrollment_secret = enrollment.secret
        self.assertEqual(enrollment.secret.quota, None)
        self.assertEqual(enrollment.secret.serial_numbers, None)
        self.assertEqual(enrollment.secret.tags.count(), 2)
        secret_data = EnrollmentSecretSerializer(enrollment_secret).data
        secret_data["id"] = 233333  # to check that there is no enrollment secret creation
        secret_data["quota"] = 23
        secret_data["request_count"] = 2331983  # to check that it cannot be updated
        serial_numbers = [get_random_string(12) for i in range(13)]
        secret_data["serial_numbers"] = serial_numbers
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(2)]
        secret_data["tags"] = [t.id for t in tags]
        data = {"configuration": enrollment.configuration.pk,
                "secret": secret_data}
        self.set_permissions("santa.change_enrollment")
        response = self.put_json_data(reverse('santa_api:enrollment', args=(enrollment.pk,)), data)
        self.assertEqual(response.status_code, 200)
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.secret, enrollment_secret)
        self.assertEqual(enrollment.secret.quota, 23)
        self.assertEqual(enrollment.secret.request_count, 0)
        self.assertEqual(enrollment.secret.serial_numbers, serial_numbers)
        self.assertEqual(
            set(enrollment.secret.tags.all()),
            set(tags)
        )

    def test_update_enrollment_unauthorized(self):
        enrollment, _ = self.force_enrollment()
        enrollment_secret = enrollment.secret
        self.assertEqual(enrollment.secret.quota, None)
        self.assertEqual(enrollment.secret.serial_numbers, None)
        secret_data = EnrollmentSecretSerializer(enrollment_secret).data
        secret_data["id"] = 233333  # to check that there is no enrollment secret creation
        secret_data["quota"] = 23
        secret_data["request_count"] = 2331983  # to check that it cannot be updated
        serial_numbers = [get_random_string(12) for i in range(13)]
        secret_data["serial_numbers"] = serial_numbers
        data = {"configuration": enrollment.configuration.pk,
                "secret": secret_data}
        self.set_permissions("santa.change_enrollment")
        response = self.put_json_data(reverse('santa_api:enrollment', args=(enrollment.pk,)), data,
                                      include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_enrollment_permission_denied(self):
        enrollment, _ = self.force_enrollment()
        enrollment_secret = enrollment.secret
        self.assertEqual(enrollment.secret.quota, None)
        self.assertEqual(enrollment.secret.serial_numbers, None)
        secret_data = EnrollmentSecretSerializer(enrollment_secret).data
        secret_data["id"] = 233333  # to check that there is no enrollment secret creation
        secret_data["quota"] = 23
        secret_data["request_count"] = 2331983  # to check that it cannot be updated
        serial_numbers = [get_random_string(12) for i in range(13)]
        secret_data["serial_numbers"] = serial_numbers
        data = {"configuration": enrollment.configuration.pk,
                "secret": secret_data}
        response = self.put_json_data(reverse('santa_api:enrollment', args=(enrollment.pk,)), data)
        self.assertEqual(response.status_code, 403)

    def test_update_enrollment_not_found(self):
        enrollment, _ = self.force_enrollment()
        enrollment_secret = enrollment.secret
        self.assertEqual(enrollment.secret.quota, None)
        self.assertEqual(enrollment.secret.serial_numbers, None)
        secret_data = EnrollmentSecretSerializer(enrollment_secret).data
        secret_data["id"] = 233333  # to check that there is no enrollment secret creation
        secret_data["quota"] = 23
        secret_data["request_count"] = 2331983  # to check that it cannot be updated
        serial_numbers = [get_random_string(12) for i in range(13)]
        secret_data["serial_numbers"] = serial_numbers
        data = {"configuration": enrollment.configuration.pk,
                "secret": secret_data}
        self.set_permissions("santa.change_enrollment")
        response = self.put_json_data(reverse("santa_api:enrollment", args=(1213028133,)), data)
        self.assertEqual(response.status_code, 404)

    # delete enrollment

    def test_delete_enrollment(self):
        enrollment, _ = self.force_enrollment()
        self.set_permissions("santa.delete_enrollment")
        response = self.delete(reverse('santa_api:enrollment', args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 204)

    def test_delete_enrollment_unauthorized(self):
        enrollment, _ = self.force_enrollment()
        self.set_permissions("santa.delete_enrollment")
        response = self.delete(reverse('santa_api:enrollment', args=(enrollment.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_enrollment_permission_denied(self):
        enrollment, _ = self.force_enrollment()
        response = self.delete(reverse('santa_api:enrollment', args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_enrollment_not_found(self):
        self.set_permissions("santa.delete_enrollment")
        response = self.delete(reverse('santa_api:enrollment', args=(1213028133,)))
        self.assertEqual(response.status_code, 404)

    # targets

    def test_targets_read_only(self):
        self.set_permissions("santa.add_target", "santa.change_target", "santa.delete_target")
        response = self.post_json_data(reverse('santa_api:targets'), {})
        self.assertEqual(response.status_code, 405)
        response = self.put_json_data(reverse('santa_api:targets'), {})
        self.assertEqual(response.status_code, 405)
        response = self.delete(reverse('santa_api:targets'))
        self.assertEqual(response.status_code, 405)

    # list targets

    def test_list_targets_unauthorized(self):
        response = self.get(reverse('santa_api:targets'), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_targets_permission_denied(self):
        response = self.get(reverse('santa_api:targets'))
        self.assertEqual(response.status_code, 403)

    def test_list_targets_filter_by_target_type_invalid(self):
        self.set_permissions("santa.view_target")
        response = self.get(reverse('santa_api:targets'), {"target_type": "INVALID"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            "target_type": ['Select a valid choice. INVALID is not one of the available choices.']
        })

    def test_list_targets_filter_by_target_type_and_target_identifier_not_found(self):
        self.set_permissions("santa.view_target")
        response = self.get(reverse('santa_api:targets'),
                            {"target_type": "BINARY", "target_identifier": get_random_string(64, "abcdef0123456789")})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'count': 0, 'next': None, 'previous': None, 'results': []})

    def test_list_targets_filter_by_target_type_and_target_identifier(self):
        self.set_permissions("santa.view_target")
        response = self.get(reverse('santa_api:targets'),
                            {"target_type": "BUNDLE", "target_identifier": self.file_sha256})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'count': 1, 'next': None, 'previous': None, 'results': [
            {
                'id': self.file_bundle_target.pk,
                'files': [],
                'certificates': [],
                'team_ids': [],
                'type': 'BUNDLE',
                'identifier': self.file_sha256
            }
        ]})

    def test_list_targets_filter_by_target_identifier_not_found(self):
        self.set_permissions("santa.view_target")
        response = self.get(reverse('santa_api:targets'),
                            {"target_identifier": get_random_string(length=64, allowed_chars='abcdef0123456789')})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'count': 0, 'next': None, 'previous': None, 'results': []})

    def test_list_targets_filter_by_target_type(self):
        self.set_permissions("santa.view_target")
        response = self.get(reverse('santa_api:targets'), {"target_type": "BINARY"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            'count': 1,
            'next': None,
            'previous': None,
            'results': [
                {
                    'id': self.file_target.pk,
                    'files': [
                        {
                            'name': self.file_target.files[0].name,
                            'path': '/Library/Frameworks/Compressor.framework/Versions/A/'
                                    'Resources/CompressorTranscoderX.bundle/Contents/MacOS',
                            'sha_256': self.file_sha256,
                            'bundle_path': '/Library/Frameworks/Compressor.framework/Versions/A/'
                                           'Resources/CompressorTranscoderX.bundle',
                            'bundle': self.file_target.files[0].bundle.pk
                        }
                    ],
                    'certificates': [],
                    'team_ids': [],
                    'type': 'BINARY',
                    'identifier': self.file_sha256
                }
            ]})

    def test_list_targets_filter_by_identifier(self):
        self.set_permissions("santa.view_target")
        response = self.get(reverse('santa_api:targets'), {"target_identifier": self.file_team_id})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            'count': 1,
            'next': None,
            'previous': None,
            'results': [
                {
                    'id': self.file_team_id_target.pk,
                    'files': [],
                    'certificates': [],
                    'team_ids': [
                        {
                            'organizational_unit': self.file_team_id,
                            'organization': 'Apple Inc.'
                        }
                    ],
                    'type': 'TEAMID',
                    'identifier': self.file_team_id
                }
            ]})

    def test_list_targets_pagination(self):
        self.set_permissions("santa.view_target")
        response = self.get(reverse('santa_api:targets'), {"page_size": 2})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['count'], 4)
        self.assertEqual(len(response.json()['results']), 2)
        self.assertEqual(response.json()['next'], 'http://testserver/api/santa/targets/?page=2&page_size=2')
        self.assertEqual(response.json()['previous'], None)

    def test_list_targets(self):
        self.set_permissions("santa.view_target")
        response = self.get(reverse('santa_api:targets'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            'count': 4,
            'next': None,
            'previous': None,
            'results': [
                {
                    'id': self.file_target.pk,
                    'files': [
                        {
                            'name': self.file_target.files[0].name,
                            'path': '/Library/Frameworks/Compressor.framework/Versions/A/'
                                    'Resources/CompressorTranscoderX.bundle/Contents/MacOS',
                            'sha_256': self.file_sha256,
                            'bundle_path': '/Library/Frameworks/Compressor.framework/Versions/A/'
                                           'Resources/CompressorTranscoderX.bundle',
                            'bundle': self.file_target.files[0].bundle.pk,
                        }
                    ],
                    'certificates': [],
                    'team_ids': [],
                    'type': 'BINARY',
                    'identifier': self.file_sha256
                },
                {
                    'id': self.file_cert_target.pk,
                    'files': [],
                    'certificates': [
                        {
                            'common_name': f'Developer ID Application: YOLO ({self.file_team_id})',
                            'organization': 'Apple Inc.',
                            'organizational_unit': self.file_team_id,
                            'domain': None,
                            'sha_256': self.file_cert_sha256,
                            'valid_from': self.file_cert_target.certificates[0].valid_from.isoformat(),
                            'valid_until': self.file_cert_target.certificates[0].valid_until.isoformat(),
                        },
                        {
                            'common_name': f'Developer ID Application: Awesome Inc ({self.file_team_id})',
                            'organization': 'Awesome Inc',
                            'organizational_unit': self.file_team_id,
                            'domain': None,
                            'sha_256': self.file_cert_sha256,
                            'valid_from': self.file_cert_target.certificates[1].valid_from.isoformat(),
                            'valid_until': self.file_cert_target.certificates[1].valid_until.isoformat(),
                        }
                    ],
                    'team_ids': [],
                    'type': 'CERTIFICATE',
                    'identifier': self.file_cert_sha256
                },
                {
                    'id': self.file_bundle_target.pk,
                    'files': [],
                    'certificates': [],
                    'team_ids': [],
                    'type': 'BUNDLE',
                    'identifier': self.file_sha256
                },
                {
                    'id': self.file_team_id_target.pk,
                    'files': [],
                    'certificates': [],
                    'team_ids': [
                        {
                            'organizational_unit': self.file_team_id,
                            'organization': 'Apple Inc.'
                        }
                    ],
                    'type': 'TEAMID',
                    'identifier': self.file_team_id
                }
            ]
        })

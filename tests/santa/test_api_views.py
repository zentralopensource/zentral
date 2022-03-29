from functools import reduce
import json
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from rest_framework import status
from rest_framework.authtoken.models import Token
import yaml
from accounts.models import User
from zentral.contrib.inventory.models import Certificate, File
from zentral.contrib.santa.models import Configuration, Rule, RuleSet, Target


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
        Token.objects.get_or_create(user=cls.service_account)
        cls.maxDiff = None

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
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.service_account.auth_token.key}"
        if dry_run is not None:
            url = f"{url}?{dry_run}"
        return self.client.post(url, data, **kwargs)

    def post_yaml_data(self, url, data, include_token=True):
        content_type = "application/yaml"
        data = yaml.dump(data)
        return self.post_data(url, data, content_type, include_token)

    def post_json_data(self, url, data, include_token=True, dry_run=None):
        content_type = "application/json"
        data = json.dumps(data)
        return self.post_data(url, data, content_type, include_token, dry_run)

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
                                    HTTP_AUTHORIZATION=f"Token {self.service_account.auth_token.key}")
        self.assertEqual(response.status_code, 403)

    def test_targets_export(self):
        self.set_permissions("santa.view_target")
        response = self.client.post(reverse("santa_api:targets_export"),
                                    HTTP_AUTHORIZATION=f"Token {self.service_account.auth_token.key}")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("task_id", response.data)
        self.assertIn("task_result_url", response.data)

    def test_team_id_targets_export(self):
        self.set_permissions("santa.view_target")
        response = self.client.post("{}?target_type=TEAMID".format(reverse("santa_api:targets_export")),
                                    HTTP_AUTHORIZATION=f"Token {self.service_account.auth_token.key}")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("task_id", response.data)
        self.assertIn("task_result_url", response.data)

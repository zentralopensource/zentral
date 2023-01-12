from functools import reduce
import json
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from rest_framework import status
import yaml
from accounts.models import User, APIToken
from zentral.conf import settings
from zentral.contrib.inventory.models import Certificate, File, EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.inventory.serializers import EnrollmentSecretSerializer
from zentral.contrib.santa.models import Configuration, Rule, RuleSet, Target, Enrollment
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

    # utils

    def force_configuration(self):
        return Configuration.objects.create(name=get_random_string(12))

    def force_enrollment(self):
        configuration = self.force_configuration()
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=self.mbu)
        return Enrollment.objects.create(configuration=configuration, secret=enrollment_secret)

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

    def force_rule(self, target_type="BINARY", target_identifier=None, configuration=None):
        if target_identifier is None:
            target_identifier = get_random_string(length=64, allowed_chars='abcdef0123456789')
        if configuration is None:
            configuration = self.configuration
        target = Target.objects.create(type=target_type, identifier=target_identifier)
        return Rule.objects.create(
            target=target,
            policy=Rule.ALLOWLIST,
            configuration=configuration,
            custom_msg="custom msg",
            description="description",
            primary_users=["yolo@example.com"]
        )

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

    def test_rule_list_post_method_not_allowed(self):
        self.set_permissions("santa.add_rule")
        response = self.client.post(reverse("santa_api:rules"),
                                    HTTP_AUTHORIZATION=f"Token {self.api_key}")
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

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
        self.assertEqual(rules[0]["target"]["type"], "BINARY")
        self.assertEqual(rules[0]["target"]["identifier"], rule.target.identifier)
        self.assertEqual(rules[0]["configuration"], self.configuration.pk)
        self.assertEqual(rules[0]["primary_users"], ["yolo@example.com"])

    def test_rule_list_by_type(self):
        self.set_permissions("santa.view_rule")
        self.force_rule()
        rule2 = self.force_rule(target_type=Target.CERTIFICATE, configuration=self.configuration2)
        response = self.client.get(reverse("santa_api:rules"),
                                   data={"type": "CERTIFICATE"},
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
                                   data={"type": "YOLO"},
                                   HTTP_AUTHORIZATION=f"Token {self.api_key}")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.json(),
            {'type': ['Select a valid choice. YOLO is not one of the available choices.']}
        )

    def test_rule_list_by_identifier(self):
        self.set_permissions("santa.view_rule")
        self.force_rule()
        rule2 = self.force_rule(target_type=Target.CERTIFICATE, configuration=self.configuration2)
        response = self.client.get(reverse("santa_api:rules"),
                                   data={"identifier": rule2.target.identifier},
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
                                   data={"configuration": self.configuration2.pk},
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
                                   data={"configuration": 12832398912},
                                   HTTP_AUTHORIZATION=f"Token {self.api_key}")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.json(),
            {'configuration': ['Select a valid choice. That choice is not one of the available choices.']}
        )

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
        enrollment = self.force_enrollment()
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
            response.json()
        )

    # filter enrollments

    def test_get_enrollments_search(self):
        enrollment1 = self.force_enrollment()
        enrollment2 = self.force_enrollment()
        enrollment3 = self.force_enrollment()
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
        enrollment = self.force_enrollment()
        self.set_permissions("santa.view_enrollment")
        response = self.get(reverse('santa_api:enrollments'), {'configuration_id': enrollment.configuration.pk},
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollments_search_permission_denied(self):
        enrollment = self.force_enrollment()
        response = self.get(reverse('santa_api:enrollments'), {'configuration_id': enrollment.configuration.pk})
        self.assertEqual(response.status_code, 403)

    # get enrollment

    def test_get_enrollment_unauthorized(self):
        enrollment = self.force_enrollment()
        self.set_permissions("santa.view_enrollment")
        response = self.get(reverse("santa_api:enrollment", args=(enrollment.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollment_permission_denied(self):
        enrollment = self.force_enrollment()
        response = self.get(reverse("santa_api:enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_not_found(self):
        self.set_permissions("santa.view_enrollment")
        response = self.get(reverse("santa_api:enrollment", args=(1213028133,)))
        self.assertEqual(response.status_code, 404)

    def test_get_enrollment(self):
        enrollment = self.force_enrollment()
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
        enrollment = self.force_enrollment()
        self.set_permissions("santa.view_enrollment")
        response = self.get(reverse("santa_api:enrollment_plist", args=(enrollment.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollment_plist_permission_denied(self):
        enrollment = self.force_enrollment()
        response = self.get(reverse("santa_api:enrollment_plist", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_plist_not_found(self):
        self.set_permissions("santa.view_enrollment")
        response = self.get(reverse("santa_api:enrollment_plist", args=(1213028133,)))
        self.assertEqual(response.status_code, 404)

    def test_get_enrollment_plist(self):
        enrollment = self.force_enrollment()
        self.set_permissions("santa.view_enrollment")
        response = self.get(reverse('santa_api:enrollment_plist', args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/x-plist')
        self.assertEqual(response['Content-Disposition'],
                         f'attachment; filename="zentral_santa_configuration.enrollment_{enrollment.pk}.plist"')
        self.assertEqual(int(response['Content-Length']), len(response.content))

    def test_get_enrollment_configuration_profile_unauthorized(self):
        enrollment = self.force_enrollment()
        self.set_permissions("santa.view_enrollment")
        response = self.get(reverse("santa_api:enrollment_configuration_profile", args=(enrollment.pk,)),
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollment_configuration_profile_permission_denied(self):
        enrollment = self.force_enrollment()
        response = self.get(reverse("santa_api:enrollment_configuration_profile", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_configuration_profile_not_found(self):
        self.set_permissions("santa.view_enrollment")
        response = self.get(reverse("santa_api:enrollment_configuration_profile", args=(1213028133,)))
        self.assertEqual(response.status_code, 404)

    def test_get_enrollment_configuration_profile(self):
        identifier = get_payload_identifier("santa_configuration")
        enrollment = self.force_enrollment()
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
        response = self.post_json_data(
            reverse('santa_api:enrollments'),
            {'configuration': config.pk,
             'secret': {"meta_business_unit": self.mbu.pk}}
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(Enrollment.objects.filter(configuration__name=config.name).count(), 1)
        enrollment = Enrollment.objects.get(configuration__name=config.name)
        self.assertEqual(enrollment.secret.meta_business_unit, self.mbu)

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
        enrollment = self.force_enrollment()
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
        response = self.put_json_data(reverse('santa_api:enrollment', args=(enrollment.pk,)), data)
        self.assertEqual(response.status_code, 200)
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.secret, enrollment_secret)
        self.assertEqual(enrollment.secret.quota, 23)
        self.assertEqual(enrollment.secret.request_count, 0)
        self.assertEqual(enrollment.secret.serial_numbers, serial_numbers)

    def test_update_enrollment_unauthorized(self):
        enrollment = self.force_enrollment()
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
        enrollment = self.force_enrollment()
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
        enrollment = self.force_enrollment()
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
        enrollment = self.force_enrollment()
        self.set_permissions("santa.delete_enrollment")
        response = self.delete(reverse('santa_api:enrollment', args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 204)

    def test_delete_enrollment_unauthorized(self):
        enrollment = self.force_enrollment()
        self.set_permissions("santa.delete_enrollment")
        response = self.delete(reverse('santa_api:enrollment', args=(enrollment.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_enrollment_permission_denied(self):
        enrollment = self.force_enrollment()
        response = self.delete(reverse('santa_api:enrollment', args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_enrollment_not_found(self):
        self.set_permissions("santa.delete_enrollment")
        response = self.delete(reverse('santa_api:enrollment', args=(1213028133,)))
        self.assertEqual(response.status_code, 404)

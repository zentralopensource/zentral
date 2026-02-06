from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.conf import settings
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.santa.models import Configuration, Enrollment
from zentral.contrib.santa.serializers import RuleUpdateSerializer, EnrollmentSerializer


class SantaSerializersTestCase(TestCase):
    def test_no_bundle_rule(self):
        data = {"rule_type": "BUNDLE",
                "identifier": get_random_string(64, "0123456789abcdef"),
                "policy": "BLOCKLIST"}
        serializer = RuleUpdateSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        ed = serializer.errors["rule_type"][0]
        self.assertEqual(str(ed), '"BUNDLE" is not a valid choice.')

    def test_rule_identifier_and_sha256(self):
        data = {"rule_type": "BINARY",
                "identifier": get_random_string(64, "0123456789abcdef"),
                "sha256": get_random_string(64, "0123456789abcdef"),
                "policy": "BLOCKLIST"}
        serializer = RuleUpdateSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        ed = serializer.errors["non_field_errors"][0]
        self.assertEqual(str(ed), "sha256 and identifier cannot be both set")

    def test_rule_missing_identifier(self):
        data = {"rule_type": "TEAMID",
                "policy": "BLOCKLIST"}
        serializer = RuleUpdateSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        ed = serializer.errors["identifier"][0]
        self.assertEqual(str(ed), "This field is required")

    def test_rule_sha(self):
        for identifier, valid in (("y", False),
                                  ("43AQ936H96", False),
                                  ("43AQ936H96:org.mozilla.firefoxdeveloperedition", False),
                                  ("a" * 64, True)):
            data = {
                "rule_type": "BINARY",
                "identifier": identifier,
                "policy": "BLOCKLIST",
            }
            s = RuleUpdateSerializer(data=data)
            self.assertEqual(s.is_valid(), valid)
            if not s.is_valid():
                ed = s.errors["identifier"][0]
                self.assertEqual(str(ed), "Invalid BINARY identifier")

    def test_rule_signing_id(self):
        for identifier, valid in (("y", False),
                                  ("43AQ936H96", False),
                                  ("43AQ936H96:org.mozilla.firefoxdeveloperedition", True),
                                  ("platform:com.apple.curl", True)):
            data = {
                "rule_type": "SIGNINGID",
                "identifier": identifier,
                "policy": "BLOCKLIST",
            }
            s = RuleUpdateSerializer(data=data)
            self.assertEqual(s.is_valid(), valid)
            if not s.is_valid():
                ed = s.errors["identifier"][0]
                self.assertEqual(str(ed), "Invalid SIGNINGID identifier")

    def test_rule_team_id(self):
        for identifier, valid in (("y", False), ("43AQ936H96", True), ("4"*64, False)):
            data = {
                "rule_type": "TEAMID",
                "identifier": identifier,
                "policy": "BLOCKLIST",
            }
            s = RuleUpdateSerializer(data=data)
            self.assertEqual(s.is_valid(), valid)
            if not s.is_valid():
                ed = s.errors["identifier"][0]
                self.assertEqual(str(ed), "Invalid TEAMID identifier")

    def test_rule_sha_signing_id_error(self):
        s = RuleUpdateSerializer(data={
            "rule_type": "SIGNINGID",
            "sha256": "a" * 64,
            "policy": "BLOCKLIST",
        })
        s.is_valid()
        sha256_errors = s.errors.get("sha256", [])
        self.assertEqual(len(sha256_errors), 1)
        self.assertEqual(str(sha256_errors[0]), "This field cannot be used in a SIGNINGID rule")

    def test_rule_sha_team_id_error(self):
        s = RuleUpdateSerializer(data={
            "rule_type": "TEAMID",
            "sha256": "a" * 64,
            "policy": "BLOCKLIST",
        })
        s.is_valid()
        sha256_errors = s.errors.get("sha256", [])
        self.assertEqual(len(sha256_errors), 1)
        self.assertEqual(str(sha256_errors[0]), "This field cannot be used in a TEAMID rule")

    def test_rule_custom_msg_allowlist(self):
        data = {"rule_type": "BINARY",
                "identifier": get_random_string(64, "0123456789abcdef"),
                "custom_msg": "yolo fomo",
                "policy": "ALLOWLIST"}
        serializer = RuleUpdateSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        ed = serializer.errors["non_field_errors"][0]
        self.assertEqual(str(ed), "Custom message cannot be set for this rule policy")

    def test_rule_custom_url_allowlist(self):
        data = {"rule_type": "BINARY",
                "identifier": get_random_string(64, "0123456789abcdef"),
                "custom_url": "https://zentral.com",
                "policy": "ALLOWLIST"}
        serializer = RuleUpdateSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        ed = serializer.errors["non_field_errors"][0]
        self.assertEqual(str(ed), "Custom URL cannot be set for this rule policy")

    def test_rule_tags_conflict(self):
        data = {"rule_type": "BINARY",
                "identifier": get_random_string(64, "0123456789abcdef"),
                "tags": ["un", "deux"],
                "excluded_tags": ["deux", "trois"],
                "policy": "BLOCKLIST"}
        serializer = RuleUpdateSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        ed = serializer.errors["non_field_errors"][0]
        self.assertEqual(str(ed), "Conflict between tags and excluded_tags")

    def test_rule_serial_numbers_conflict(self):
        data = {"rule_type": "BINARY",
                "identifier": get_random_string(64, "0123456789abcdef"),
                "serial_numbers": ["un", "deux"],
                "excluded_serial_numbers": ["deux", "trois"],
                "policy": "BLOCKLIST"}
        serializer = RuleUpdateSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        ed = serializer.errors["non_field_errors"][0]
        self.assertEqual(str(ed), "Conflict between serial_numbers and excluded_serial_numbers")

    def test_rule_primary_users_conflict(self):
        data = {"rule_type": "BINARY",
                "identifier": get_random_string(64, "0123456789abcdef"),
                "primary_users": ["un", "deux"],
                "excluded_primary_users": ["deux", "trois"],
                "policy": "BLOCKLIST"}
        serializer = RuleUpdateSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        ed = serializer.errors["non_field_errors"][0]
        self.assertEqual(str(ed), "Conflict between primary_users and excluded_primary_users")

    # Enrollment serializer

    def test_enrollment_plist_download_url(self):
        base_url = f'https://{settings["api"]["fqdn"]}'
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        mbu.create_enrollment_business_unit()
        configuration = Configuration.objects.create(name=get_random_string(12))
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=mbu)
        enrollment = Enrollment.objects.create(configuration=configuration, secret=enrollment_secret)
        serializer = EnrollmentSerializer(instance=enrollment)

        self.assertEqual(
            serializer.get_plist_download_url(enrollment),
            f'{base_url}{reverse("santa_api:enrollment_plist", args=(enrollment.pk,))}'
        )

    def test_enrollment_configuration_profile_download_url(self):
        base_url = f'https://{settings["api"]["fqdn"]}'
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        mbu.create_enrollment_business_unit()
        configuration = Configuration.objects.create(name=get_random_string(12))
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=mbu)
        enrollment = Enrollment.objects.create(configuration=configuration, secret=enrollment_secret)
        serializer = EnrollmentSerializer(instance=enrollment)
        self.assertEqual(
            serializer.get_configuration_profile_download_url(enrollment),
            f'{base_url}{reverse("santa_api:enrollment_configuration_profile", args=(enrollment.pk,))}'
        )

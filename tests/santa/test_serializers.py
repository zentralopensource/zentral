from django.test import SimpleTestCase
from django.utils.crypto import get_random_string
from zentral.contrib.santa.serializers import RuleUpdateSerializer


class SantaSerializersTestCase(SimpleTestCase):
    def test_rule_wrong_policy_for_bundle_rule(self):
        data = {"rule_type": "BUNDLE",
                "identifier": get_random_string(64, "0123456789abcdef"),
                "policy": "BLOCKLIST"}
        serializer = RuleUpdateSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        ed = serializer.errors["non_field_errors"][0]
        self.assertEqual(str(ed), "Wrong policy for BUNDLE rule")

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

    def test_rule_team_id_sha256(self):
        data = {"rule_type": "TEAMID",
                "sha256": get_random_string(64, "0123456789abcdef"),
                "policy": "BLOCKLIST"}
        serializer = RuleUpdateSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        ed = serializer.errors["sha256"][0]
        self.assertEqual(str(ed), "This field cannot be used in a Team ID rule")

    def test_rule_bad_team_id_identifier(self):
        data = {"rule_type": "TEAMID",
                "identifier": get_random_string(24),
                "policy": "BLOCKLIST"}
        serializer = RuleUpdateSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        ed = serializer.errors["identifier"][0]
        self.assertEqual(str(ed), "Invalid Team ID")

    def test_rule_bad_sha256_identifier(self):
        data = {"rule_type": "BINARY",
                "identifier": get_random_string(24),
                "policy": "BLOCKLIST"}
        serializer = RuleUpdateSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        ed = serializer.errors["identifier"][0]
        self.assertEqual(str(ed), "Invalid sha256")

    def test_rule_custom_msg_allowlist(self):
        data = {"rule_type": "BINARY",
                "identifier": get_random_string(64, "0123456789abcdef"),
                "custom_msg": "yolo fomo",
                "policy": "ALLOWLIST"}
        serializer = RuleUpdateSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        ed = serializer.errors["non_field_errors"][0]
        self.assertEqual(str(ed), "Custom message can only be set on BLOCKLIST rules")

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

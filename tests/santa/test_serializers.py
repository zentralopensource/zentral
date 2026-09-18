from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from zentral.conf import settings
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit, Tag
from zentral.contrib.santa.models import Configuration, Enrollment, Rule, Target
from zentral.contrib.santa.serializers import (ConfigurationSerializer, EnrollmentSerializer,
                                               RuleSerializer, RuleUpdateSerializer)
from .utils import force_configuration, force_realm, force_rule


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

    def test_rule_compiler_policy_incompatible_rule_type(self):
        for rule_type, identifier in (("TEAMID", "43AQ936H96"),
                                      ("CERTIFICATE", get_random_string(64, "0123456789abcdef"))):
            with self.subTest(rule_type):
                data = {"rule_type": rule_type,
                        "identifier": identifier,
                        "policy": "ALLOWLIST_COMPILER"}
                serializer = RuleUpdateSerializer(data=data)
                self.assertFalse(serializer.is_valid())
                ed = serializer.errors["policy"][0]
                self.assertEqual(str(ed), Target.Type.compiler_policy_error())

    def test_rule_compiler_policy(self):
        for rule_type, identifier in (("CDHASH", get_random_string(40, "0123456789abcdef")),
                                      ("BINARY", get_random_string(64, "0123456789abcdef")),
                                      ("SIGNINGID", "43AQ936H96:org.mozilla.firefoxdeveloperedition")):
            with self.subTest(rule_type):
                data = {"rule_type": rule_type,
                        "identifier": identifier,
                        "policy": "ALLOWLIST_COMPILER"}
                serializer = RuleUpdateSerializer(data=data)
                self.assertTrue(serializer.is_valid())

    def test_rule_custom_msg_allowlist(self):
        data = {"rule_type": "BINARY",
                "identifier": get_random_string(64, "0123456789abcdef"),
                "custom_msg": "yolo fomo",
                "policy": "ALLOWLIST"}
        serializer = RuleUpdateSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        ed = serializer.errors["non_field_errors"][0]
        self.assertEqual(str(ed), "Custom message cannot be set for this rule policy")

    def test_rule_custom_url_length(self):
        custom_url = f"https://zentral.com/{get_random_string(240)}"
        data = {"rule_type": "BINARY",
                "identifier": get_random_string(64, "0123456789abcdef"),
                "custom_url": custom_url,
                "policy": "BLOCKLIST"}
        serializer = RuleUpdateSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        custom_url = f"https://zentral.com/{get_random_string(840)}"
        data = {"rule_type": "BINARY",
                "identifier": get_random_string(64, "0123456789abcdef"),
                "custom_url": custom_url,
                "policy": "BLOCKLIST"}
        serializer = RuleUpdateSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        ed = serializer.errors["custom_url"][0]
        self.assertEqual(str(ed), "Ensure this field has no more than 800 characters.")

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


class SantaConfigurationSerializerTestCase(TestCase):
    def test_voting_portal_event_detail_source_requires_a_portal(self):
        serializer = ConfigurationSerializer(data={
            "name": get_random_string(12),
            "event_detail_source": Configuration.EventDetailSource.VOTING_PORTAL,
        })
        self.assertFalse(serializer.is_valid())
        self.assertEqual(
            serializer.errors["event_detail_source"],
            ["Requires a voting realm with the user portal enabled"]
        )

    def test_custom_event_detail_source_requires_an_url(self):
        serializer = ConfigurationSerializer(data={
            "name": get_random_string(12),
            "event_detail_source": Configuration.EventDetailSource.CUSTOM,
        })
        self.assertFalse(serializer.is_valid())
        self.assertEqual(serializer.errors["event_detail_url"], ["This field is required"])

    def test_voting_portal_event_detail_source(self):
        realm = force_realm(user_portal=True)
        serializer = ConfigurationSerializer(data={
            "name": get_random_string(12),
            "voting_realm": realm.pk,
            "event_detail_source": Configuration.EventDetailSource.VOTING_PORTAL,
        })
        self.assertTrue(serializer.is_valid(), serializer.errors)

    def test_event_detail_source_defaults_to_local_when_omitted(self):
        serializer = ConfigurationSerializer(data={"name": get_random_string(12)})
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(serializer.save().event_detail_source, Configuration.EventDetailSource.LOCAL)

    # an update carries the whole event detail, or none of it

    def test_update_with_one_event_detail_attribute(self):
        configuration = force_configuration()
        serializer = ConfigurationSerializer(
            configuration, data={"name": configuration.name, "event_detail_url": ""}
        )
        self.assertFalse(serializer.is_valid())
        self.assertEqual(
            {attr: [str(e) for e in errors] for attr, errors in serializer.errors.items()},
            {"event_detail_source": ["This field is required when the event detail changes"],
             "event_detail_text": ["This field is required when the event detail changes"]}
        )

    def test_update_with_the_whole_event_detail(self):
        configuration = force_configuration()
        serializer = ConfigurationSerializer(configuration, data={
            "name": configuration.name,
            "event_detail_source": Configuration.EventDetailSource.CUSTOM,
            "event_detail_url": "https://www.example.com/santa",
            "event_detail_text": "Why?",
        })
        self.assertTrue(serializer.is_valid(), serializer.errors)

    def test_update_to_a_custom_source_without_an_url(self):
        configuration = force_configuration()
        serializer = ConfigurationSerializer(configuration, data={
            "name": configuration.name,
            "event_detail_source": Configuration.EventDetailSource.CUSTOM,
            "event_detail_url": "",
            "event_detail_text": "Why?",
        })
        self.assertFalse(serializer.is_valid())
        self.assertEqual([str(e) for e in serializer.errors["event_detail_url"]], ["This field is required"])

    def test_update_that_leaves_the_event_detail_alone(self):
        configuration = force_configuration()
        serializer = ConfigurationSerializer(configuration, data={"name": get_random_string(12)})
        self.assertTrue(serializer.is_valid(), serializer.errors)

    def test_update_to_a_local_source_clears_the_url_and_the_label(self):
        configuration = force_configuration(
            event_detail_source=Configuration.EventDetailSource.CUSTOM,
            event_detail_url="https://www.example.com/santa",
            event_detail_text="Why?",
        )
        serializer = ConfigurationSerializer(configuration, data={
            "name": configuration.name,
            "event_detail_source": Configuration.EventDetailSource.LOCAL,
            "event_detail_url": "https://www.example.com/santa",
            "event_detail_text": "Why?",
        })
        self.assertTrue(serializer.is_valid(), serializer.errors)
        configuration = serializer.save()
        self.assertEqual(configuration.event_detail_url, "")
        self.assertEqual(configuration.event_detail_text, "")

    def test_update_to_a_voting_portal_source_clears_the_url_and_keeps_the_label(self):
        configuration = force_configuration(
            voting_realm=force_realm(user_portal=True),
            event_detail_source=Configuration.EventDetailSource.CUSTOM,
            event_detail_url="https://www.example.com/santa",
        )
        serializer = ConfigurationSerializer(configuration, data={
            "name": configuration.name,
            "event_detail_source": Configuration.EventDetailSource.VOTING_PORTAL,
            "event_detail_url": "https://www.example.com/santa",
            "event_detail_text": "Why?",
        })
        self.assertTrue(serializer.is_valid(), serializer.errors)
        configuration = serializer.save()
        self.assertEqual(configuration.event_detail_url, "")
        self.assertEqual(configuration.event_detail_text, "Why?")

    # the source and the voting realm are read against each other

    def test_update_to_a_voting_portal_source_reads_the_stored_realm(self):
        configuration = force_configuration(voting_realm=force_realm(user_portal=True))
        serializer = ConfigurationSerializer(configuration, data={
            "name": configuration.name,
            "event_detail_source": Configuration.EventDetailSource.VOTING_PORTAL,
            "event_detail_url": "",
            "event_detail_text": "",
        })
        self.assertTrue(serializer.is_valid(), serializer.errors)

    def test_update_to_a_voting_portal_source_without_a_stored_realm(self):
        configuration = force_configuration()
        serializer = ConfigurationSerializer(configuration, data={
            "name": configuration.name,
            "event_detail_source": Configuration.EventDetailSource.VOTING_PORTAL,
            "event_detail_url": "",
            "event_detail_text": "",
        })
        self.assertFalse(serializer.is_valid())
        self.assertEqual(
            [str(e) for e in serializer.errors["event_detail_source"]],
            ["Requires a voting realm with the user portal enabled"]
        )

    def test_update_that_clears_the_realm_of_a_voting_portal_configuration(self):
        configuration = force_configuration(
            voting_realm=force_realm(user_portal=True),
            event_detail_source=Configuration.EventDetailSource.VOTING_PORTAL,
        )
        serializer = ConfigurationSerializer(
            configuration, data={"name": configuration.name, "voting_realm": None}
        )
        self.assertFalse(serializer.is_valid())
        self.assertEqual(
            [str(e) for e in serializer.errors["event_detail_source"]],
            ["Requires a voting realm with the user portal enabled"]
        )

    def test_update_that_names_neither_side_does_not_read_them(self):
        realm = force_realm(user_portal=True)
        configuration = force_configuration(
            voting_realm=realm,
            event_detail_source=Configuration.EventDetailSource.VOTING_PORTAL,
        )
        realm.user_portal = False
        realm.save()
        serializer = ConfigurationSerializer(configuration, data={"name": get_random_string(12)})
        self.assertTrue(serializer.is_valid(), serializer.errors)

    def test_event_detail_source_cannot_be_blank(self):
        serializer = ConfigurationSerializer(data={"name": get_random_string(12), "event_detail_source": ""})
        self.assertFalse(serializer.is_valid())
        self.assertEqual([str(e) for e in serializer.errors["event_detail_source"]], ['"" is not a valid choice.'])


class SantaRuleSerializerTestCase(TestCase):
    def body(self, rule, **extra):
        return {"configuration": rule.configuration.pk,
                "policy": rule.policy,
                "target_type": rule.target.type,
                "target_identifier": rule.target.identifier,
                **extra}

    # an attribute the body leaves out is cleared

    def test_update_clears_the_scope_the_body_leaves_out(self):
        tag = Tag.objects.create(name=get_random_string(12))
        rule = force_rule(serial_numbers=["ABCD"], primary_users=["yolo@example.com"])
        rule.tags.set([tag])
        serializer = RuleSerializer(rule, data=self.body(rule, description="updated"))
        self.assertTrue(serializer.is_valid(), serializer.errors)
        rule = serializer.save()
        self.assertEqual(rule.serial_numbers, [])
        self.assertEqual(rule.primary_users, [])
        self.assertEqual(rule.tags.count(), 0)
        self.assertEqual(rule.description, "updated")

    def test_update_excluding_what_the_stored_rule_included(self):
        rule = force_rule(serial_numbers=["ABCD"])
        serializer = RuleSerializer(rule, data=self.body(rule, excluded_serial_numbers=["ABCD"]))
        self.assertTrue(serializer.is_valid(), serializer.errors)
        rule = serializer.save()
        self.assertEqual(rule.serial_numbers, [])
        self.assertEqual(rule.excluded_serial_numbers, ["ABCD"])

    def test_update_refuses_a_scope_the_body_puts_on_both_sides(self):
        rule = force_rule()
        serializer = RuleSerializer(rule, data=self.body(rule,
                                                         serial_numbers=["ABCD"],
                                                         excluded_serial_numbers=["ABCD"]))
        self.assertFalse(serializer.is_valid())
        self.assertEqual([str(e) for e in serializer.errors["serial_numbers"]],
                         ["'ABCD' in both included and excluded"])

    def test_update_to_a_policy_that_refuses_a_custom_msg_clears_it(self):
        rule = force_rule(policy=Rule.Policy.BLOCKLIST)
        rule.custom_msg = "custom msg"
        rule.save()
        serializer = RuleSerializer(rule, data=self.body(rule, policy=Rule.Policy.ALLOWLIST))
        self.assertTrue(serializer.is_valid(), serializer.errors)
        rule = serializer.save()
        self.assertEqual(rule.policy, Rule.Policy.ALLOWLIST)
        self.assertEqual(rule.custom_msg, "")

    def test_update_refuses_a_custom_msg_the_policy_does_not_accept(self):
        rule = force_rule(policy=Rule.Policy.BLOCKLIST)
        serializer = RuleSerializer(rule, data=self.body(rule,
                                                         policy=Rule.Policy.ALLOWLIST,
                                                         custom_msg="custom msg"))
        self.assertFalse(serializer.is_valid())
        self.assertEqual([str(e) for e in serializer.errors["custom_msg"]],
                         ["Cannot be set for this rule policy"])

    def test_update_away_from_cel_clears_the_expression(self):
        rule = force_rule(policy=Rule.Policy.CEL, cel_expr="target.signing_time_unix >= 1")
        serializer = RuleSerializer(rule, data=self.body(rule, policy=Rule.Policy.BLOCKLIST))
        self.assertTrue(serializer.is_valid(), serializer.errors)
        rule = serializer.save()
        self.assertEqual(rule.policy, Rule.Policy.BLOCKLIST)
        self.assertEqual(rule.cel_expr, "")

    def test_update_to_cel_without_the_expression(self):
        rule = force_rule(policy=Rule.Policy.CEL, cel_expr="target.signing_time_unix >= 1")
        serializer = RuleSerializer(rule, data=self.body(rule, description="updated"))
        self.assertFalse(serializer.is_valid())
        self.assertEqual([str(e) for e in serializer.errors["cel_expr"]],
                         ["This field is required for CEL rules"])

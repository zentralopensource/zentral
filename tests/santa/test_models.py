import datetime
from django.core.exceptions import ValidationError
from django.test import TestCase
from zentral.contrib.santa.models import EnrolledMachine, Rule, Target
from tests.zentral_test_utils.assertions.serialization_assertions import SerializeForEventAssertions
from .utils import (add_file_to_test_class, force_ballot, force_configuration, force_enrolled_machine,
                    force_realm_user, force_target, force_target_state, force_voting_group)


class SantaTargetModelTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        add_file_to_test_class(cls)

    # get_targets_display_strings

    def test_get_targets_display_strings_signing_id(self):
        key = (Target.Type.SIGNING_ID, self.file_signing_id)
        self.assertEqual(
            Target.objects.get_targets_display_strings([key]),
            {key: self.file_name}
        )

    def test_get_targets_display_strings_binary(self):
        key = (Target.Type.BINARY, self.file_sha256)
        self.assertEqual(
            Target.objects.get_targets_display_strings([key]),
            {key: self.file_name}
        )

    def test_get_targets_display_strings_cdhash(self):
        key = (Target.Type.CDHASH, self.cdhash)
        self.assertEqual(
            Target.objects.get_targets_display_strings([key]),
            {key: self.file_name}
        )

    def test_get_targets_display_strings_team_id(self):
        key = (Target.Type.TEAM_ID, self.file_team_id)
        self.assertEqual(
            Target.objects.get_targets_display_strings([key]),
            {key: "Apple Inc."}
        )

    def test_get_targets_display_strings_certificate(self):
        key = (Target.Type.CERTIFICATE, self.file_cert_sha256)
        self.assertEqual(
            Target.objects.get_targets_display_strings([key]),
            {key: "Apple Inc."}
        )

    def test_get_targets_display_strings_bundle(self):
        key = (Target.Type.BUNDLE, self.bundle_sha256)
        self.assertEqual(
            Target.objects.get_targets_display_strings([key]),
            {key: f"{self.file_bundle_name} 3.5.3"}
        )

    def test_get_targets_display_strings_metabundle(self):
        key = (Target.Type.METABUNDLE, self.metabundle_sha256)
        self.assertEqual(
            Target.objects.get_targets_display_strings([key]),
            {key: self.file_bundle_name}
        )

    def test_get_targets_display_strings_all(self):
        keys = [
            (Target.Type.SIGNING_ID, self.file_signing_id),
            (Target.Type.BINARY, self.file_sha256),
            (Target.Type.CDHASH, self.cdhash),
            (Target.Type.TEAM_ID, self.file_team_id),
            (Target.Type.CERTIFICATE, self.file_cert_sha256),
            (Target.Type.BUNDLE, self.bundle_sha256),
            (Target.Type.METABUNDLE, self.metabundle_sha256)
        ]
        self.assertEqual(
            Target.objects.get_targets_display_strings(keys),
            {(Target.Type.SIGNING_ID, self.file_signing_id): self.file_name,
             (Target.Type.BINARY, self.file_sha256): self.file_name,
             (Target.Type.CDHASH, self.cdhash): self.file_name,
             (Target.Type.TEAM_ID, self.file_team_id): "Apple Inc.",
             (Target.Type.CERTIFICATE, self.file_cert_sha256): "Apple Inc.",
             (Target.Type.BUNDLE, self.bundle_sha256): f"{self.file_bundle_name} 3.5.3",
             (Target.Type.METABUNDLE, self.metabundle_sha256): self.file_bundle_name}
        )

    def test_get_targets_display_strings_none(self):
        self.assertEqual(
            Target.objects.get_targets_display_strings([]),
            {}
        )


class SantaSerializationTestCase(TestCase, SerializeForEventAssertions):
    maxDiff = None

    def test_serialize_for_event_is_json_native(self):
        configuration = force_configuration()
        _, realm_user = force_realm_user()
        target = force_target()
        ballot = force_ballot(target, realm_user, [(configuration, True, 1)])
        for obj in (configuration,
                    force_voting_group(configuration, realm_user),
                    force_target_state(configuration=configuration),
                    ballot,
                    ballot.vote_set.first(),
                    force_enrolled_machine(configuration=configuration,
                                           forced_sync_type=EnrolledMachine.SyncType.CLEAN_ALL,
                                           last_sync_ok=True,
                                           last_postflight_at=datetime.datetime(
                                               2026, 8, 20, 12, tzinfo=datetime.UTC))):
            with self.subTest(obj._meta.model_name):
                self.assert_serialize_for_event_is_json_native(obj)

    def test_enrolled_machine_serialize_for_event_keys_only(self):
        configuration = force_configuration()
        enrolled_machine = force_enrolled_machine(configuration=configuration)
        self.assertEqual(
            enrolled_machine.serialize_for_event(keys_only=True),
            {"pk": enrolled_machine.pk,
             "hardware_uuid": str(enrolled_machine.hardware_uuid),
             "serial_number": enrolled_machine.serial_number}
        )

    def test_enrolled_machine_serialize_for_event(self):
        configuration = force_configuration()
        enrolled_machine = force_enrolled_machine(
            configuration=configuration,
            forced_sync_type=EnrolledMachine.SyncType.CLEAN_ALL,
        )
        serialized = enrolled_machine.serialize_for_event()
        # the keys_only form is the head of the full one
        self.assertEqual(
            {k: serialized[k] for k in ("pk", "hardware_uuid", "serial_number")},
            enrolled_machine.serialize_for_event(keys_only=True)
        )
        self.assertEqual(serialized["configuration"],
                         {"pk": configuration.pk, "name": configuration.name})
        self.assertEqual(serialized["forced_sync_type"], "CLEAN_ALL")
        self.assertEqual(serialized["forced_sync_type_at"], "2026-08-20T12:00:00+00:00")
        self.assertIsNone(serialized["last_preflight_at"])
        # the sync session is an implementation detail of the sync protocol
        self.assertNotIn("sync_session", serialized)


class SantaRuleModelTestCase(TestCase):
    maxDiff = None

    # compiler policy target types

    def test_compatible_with_compiler_policy(self):
        # the order is the one the error message enumerates
        self.assertEqual([member.value for member in Target.Type if member.compatible_with_compiler_policy],
                         ["SIGNINGID", "BINARY", "CDHASH"])

    def test_compiler_policy_error(self):
        self.assertEqual(Target.Type.compiler_policy_error(),
                         "Only available for SIGNINGID, BINARY, CDHASH targets")

    # clean

    def _clean_rule(self, target_type, policy):
        rule = Rule(configuration=force_configuration(),
                    target=force_target(target_type),
                    policy=policy)
        # the ruleset FK is nullable but not blank, and no rule form offers it
        rule.full_clean(exclude=["ruleset"])

    def test_clean_compiler_policy_incompatible_target_type(self):
        for target_type in (Target.Type.TEAM_ID, Target.Type.CERTIFICATE):
            with self.subTest(target_type):
                with self.assertRaises(ValidationError) as cm:
                    self._clean_rule(target_type, Rule.Policy.ALLOWLIST_COMPILER)
                self.assertEqual(cm.exception.message_dict, {"policy": [Target.Type.compiler_policy_error()]})

    def test_clean_compiler_policy_compatible_target_type(self):
        for target_type in (Target.Type.CDHASH, Target.Type.BINARY, Target.Type.SIGNING_ID):
            with self.subTest(target_type):
                self._clean_rule(target_type, Rule.Policy.ALLOWLIST_COMPILER)

    def test_clean_other_policy_any_target_type(self):
        for target_type in (Target.Type.TEAM_ID, Target.Type.CERTIFICATE):
            with self.subTest(target_type):
                self._clean_rule(target_type, Rule.Policy.ALLOWLIST)

    def test_clean_incomplete_rule(self):
        for target, policy in ((None, Rule.Policy.ALLOWLIST_COMPILER),
                               (force_target(Target.Type.TEAM_ID), None),
                               (force_target(Target.Type.TEAM_ID), 42)):
            with self.subTest(policy=policy, target=target):
                Rule(configuration=force_configuration(), target=target, policy=policy).clean()

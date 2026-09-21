import datetime
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils.crypto import get_random_string
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


class SantaCurrentEnrollmentTestCase(TestCase):
    """A machine is a serial number, and its current enrollment is the row the device talks to."""

    @staticmethod
    def at(day):
        return datetime.datetime(2026, 9, day, tzinfo=datetime.UTC)

    def test_no_enrolled_machine(self):
        self.assertIsNone(EnrolledMachine.objects.current_for_serial_number(get_random_string(12)))

    def test_last_preflight_decides_not_last_save(self):
        serial_number = get_random_string(12)
        current = force_enrolled_machine(serial_number=serial_number, last_preflight_at=self.at(2))
        stale = force_enrolled_machine(serial_number=serial_number, last_preflight_at=self.at(1))
        # an admin queueing a clean sync on the stale row saves it, and updated_at is auto_now
        stale.save()
        self.assertEqual(EnrolledMachine.objects.current_for_serial_number(serial_number), current)
        self.assertEqual(list(EnrolledMachine.objects.for_serial_number(serial_number)), [current, stale])

    def test_row_without_preflight_is_last(self):
        serial_number = get_random_string(12)
        never = force_enrolled_machine(serial_number=serial_number)
        current = force_enrolled_machine(serial_number=serial_number, last_preflight_at=self.at(1))
        self.assertEqual(EnrolledMachine.objects.current_for_serial_number(serial_number), current)
        self.assertEqual(list(EnrolledMachine.objects.for_serial_number(serial_number)), [current, never])

    def test_rows_without_preflight_ordered_by_creation(self):
        serial_number = get_random_string(12)
        first = force_enrolled_machine(serial_number=serial_number)
        last = force_enrolled_machine(serial_number=serial_number)
        self.assertEqual(EnrolledMachine.objects.current_for_serial_number(serial_number), last)
        self.assertEqual(list(EnrolledMachine.objects.for_serial_number(serial_number)), [last, first])

    def test_current_for_serial_numbers_one_row_per_serial(self):
        serial_number = get_random_string(12)
        current = force_enrolled_machine(serial_number=serial_number, last_preflight_at=self.at(2))
        force_enrolled_machine(serial_number=serial_number, last_preflight_at=self.at(1))
        other = force_enrolled_machine(last_preflight_at=self.at(3))
        self.assertEqual(
            set(EnrolledMachine.objects.current_for_serial_numbers().values_list("pk", flat=True)),
            {current.pk, other.pk},
        )
        # a filter on the result applies to the current rows, not to the stale ones
        self.assertEqual(
            [em.pk for em in EnrolledMachine.objects.current_for_serial_numbers()
                                                    .filter(serial_number=serial_number)],
            [current.pk],
        )

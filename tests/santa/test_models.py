from django.test import TestCase
from zentral.contrib.santa.models import Target
from tests.zentral_test_utils.assertions.serialization_assertions import SerializeForEventAssertions
from .utils import (add_file_to_test_class, force_ballot, force_configuration, force_realm_user,
                    force_target, force_target_state, force_voting_group)


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
    def test_serialize_for_event_is_json_native(self):
        configuration = force_configuration()
        _, realm_user = force_realm_user()
        target = force_target()
        ballot = force_ballot(target, realm_user, [(configuration, True, 1)])
        for obj in (configuration,
                    force_voting_group(configuration, realm_user),
                    force_target_state(configuration=configuration),
                    ballot,
                    ballot.vote_set.first()):
            with self.subTest(obj._meta.model_name):
                self.assert_serialize_for_event_is_json_native(obj)

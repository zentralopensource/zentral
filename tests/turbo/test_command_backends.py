from django.test import TestCase
from rest_framework import serializers
from zentral.contrib.turbo.command_backends import (CommandBackend, get_command_backend,
                                                    get_command_backend_class)
from zentral.contrib.turbo.command_backends.base import BaseCommand
from zentral.contrib.turbo.command_backends.file_export import (DEFAULT_MAX_SIZE, MAX_MAX_SIZE,
                                                                MAX_PATTERNS)
from zentral.contrib.turbo.models import Job, ScheduleMode
from .utils import force_command


class TurboCommandBackendsTestCase(TestCase):
    maxDiff = None

    # the registry

    def test_every_backend_resolves(self):
        for backend in CommandBackend:
            self.assertIs(get_command_backend_class(backend).kind, backend)

    def test_unknown_backend(self):
        # The raise is the only gate. A value in CommandBackend that the factory does not map
        # fails here, and does not return None.
        with self.assertRaises(ValueError) as cm:
            get_command_backend_class("not_a_backend")
        self.assertIn("not_a_backend", str(cm.exception))

    def test_base_command_wire_payload_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            BaseCommand.wire_payload(None)

    def test_every_backend_is_a_job_kind(self):
        # Job.kind is the wire kind and the backend value. A backend without a kind exists, but
        # no operator can schedule it.
        for backend in CommandBackend:
            self.assertIn(backend.value, Job.Kind.values)

    # the declarations every backend owes

    def test_every_backend_declares_allowed_modes(self):
        for backend in CommandBackend:
            self.assertTrue(get_command_backend_class(backend).allowed_modes,
                            f"{backend} declares no allowed_modes, so it is schedulable nowhere")

    def test_every_backend_declares_artifacts(self):
        for backend in CommandBackend:
            backend_class = get_command_backend_class(backend)
            self.assertTrue(backend_class.artifacts,
                            f"{backend} declares no artifacts, so a run produces nothing")
            names = [artifact.name for artifact in backend_class.artifacts]
            self.assertEqual(len(names), len(set(names)), f"{backend} declares a duplicate artifact name")

    def test_every_artifact_is_reachable_by_name(self):
        for backend in CommandBackend:
            backend_class = get_command_backend_class(backend)
            for artifact in backend_class.artifacts:
                self.assertIs(backend_class.get_artifact(artifact.name), artifact)
            self.assertIsNone(backend_class.get_artifact("not_an_artifact"))

    def test_every_upload_capable_backend_is_one_time_only(self):
        # One key for each run lets a retry overwrite the object. A kind with a recurring
        # schedule needs a run identity, which the mint request does not carry yet. It would
        # overwrite the artifact of the previous run.
        for backend in CommandBackend:
            backend_class = get_command_backend_class(backend)
            if backend_class.requires_upload:
                self.assertEqual(backend_class.allowed_modes, frozenset([ScheduleMode.ONE_TIME]))

    # allowed schedule modes

    def test_command_kinds_are_one_time_only(self):
        for backend in CommandBackend:
            self.assertEqual(Job.allowed_schedule_modes(backend.value), frozenset([ScheduleMode.ONE_TIME]))

    def test_non_command_kinds_take_every_mode(self):
        for kind in (Job.Kind.SCRIPT, Job.Kind.MSCP_CHECK):
            self.assertEqual(Job.allowed_schedule_modes(kind), frozenset(ScheduleMode.values))

    def test_kinds_for_schedule_mode(self):
        self.assertEqual(sorted(Job.kinds_for_schedule_mode(ScheduleMode.RECURRING)),
                         sorted([Job.Kind.SCRIPT.value, Job.Kind.MSCP_CHECK.value]))
        self.assertEqual(sorted(Job.kinds_for_schedule_mode(ScheduleMode.ONE_TIME)),
                         sorted(Job.Kind.values))

    # sysdiagnose

    def test_sysdiagnose_wire_payload_is_empty(self):
        command = force_command(backend=CommandBackend.SYSDIAGNOSE)
        self.assertEqual(command.wire_payload(), {})

    def test_sysdiagnose_one_artifact(self):
        backend = get_command_backend(force_command(backend=CommandBackend.SYSDIAGNOSE))
        artifact, = backend.artifacts
        self.assertEqual(artifact.name, "archive")
        self.assertEqual(artifact.extension, ".tar.gz")
        self.assertFalse(artifact.optional)

    def test_sysdiagnose_kwargs_serializer_has_no_fields(self):
        # No options: an operator starts one from a machine page with one click, and the API
        # accepts a create with no kwargs block.
        backend_class = get_command_backend_class(CommandBackend.SYSDIAGNOSE)
        self.assertEqual(backend_class.kwargs_serializer().fields, {})

    # file_export

    def test_file_export_wire_payload(self):
        command = force_command(backend=CommandBackend.FILE_EXPORT,
                                backend_kwargs={"patterns": ["/var/log/*.log"], "max_size": 2048})
        self.assertEqual(command.wire_payload(), {"patterns": ["/var/log/*.log"], "max_size": 2048})

    def test_file_export_two_artifacts_archive_optional(self):
        backend_class = get_command_backend_class(CommandBackend.FILE_EXPORT)
        manifest, archive = backend_class.artifacts
        self.assertEqual(manifest.name, "manifest")
        self.assertEqual(manifest.extension, ".json")
        self.assertFalse(manifest.optional, "the manifest is always produced, even by a zero-match run")
        self.assertEqual(archive.name, "archive")
        self.assertEqual(archive.extension, ".zip")
        self.assertTrue(archive.optional, "a zero-match run has nothing to archive")

    def _validate_file_export(self, kwargs):
        serializer = get_command_backend_class(CommandBackend.FILE_EXPORT).kwargs_serializer(data=kwargs)
        serializer.is_valid(raise_exception=True)
        return serializer.validated_data

    def test_file_export_max_size_default(self):
        data = self._validate_file_export({"patterns": ["/var/log/install.log"]})
        self.assertEqual(data["max_size"], DEFAULT_MAX_SIZE)

    def test_file_export_max_size_above_absolute(self):
        with self.assertRaises(serializers.ValidationError) as cm:
            self._validate_file_export({"patterns": ["/tmp/x"], "max_size": MAX_MAX_SIZE + 1})
        self.assertIn("max_size", cm.exception.detail)

    def test_file_export_relative_pattern(self):
        with self.assertRaises(serializers.ValidationError) as cm:
            self._validate_file_export({"patterns": ["var/log/install.log"]})
        self.assertEqual(cm.exception.detail["patterns"][0][0], "Must be an absolute path")

    def test_file_export_parent_segment(self):
        # A .. segment leaves the directory that the pattern names. Zentral rejects the segment
        # and does not normalize it, so the agent walks what the operator reads.
        with self.assertRaises(serializers.ValidationError) as cm:
            self._validate_file_export({"patterns": ["/var/log/../../etc/shadow"]})
        self.assertEqual(cm.exception.detail["patterns"][0][0], "Must not contain a .. segment")

    def test_file_export_recursive_wildcard(self):
        # fnmatch accepts **, and reads two stars as one. With FNM_PATHNAME,
        # "/Library/Logs/**/*.log" matches one level, not two. A pattern for a recursive walk
        # collects one level with no error, which is worse than an error.
        with self.assertRaises(serializers.ValidationError) as cm:
            self._validate_file_export({"patterns": ["/Library/Logs/**/*.log"]})
        self.assertIn("no recursive wildcard", cm.exception.detail["patterns"][0][0])

    def test_file_export_single_wildcard_per_level_is_fine(self):
        # one pattern for each level
        data = self._validate_file_export(
            {"patterns": ["/Library/Logs/*.log", "/Library/Logs/*/*.log", "/Library/Logs/*/*/*.log"]})
        self.assertEqual(len(data["patterns"]), 3)

    def test_file_export_parent_in_a_filename_is_fine(self):
        # Only a complete ".." segment leaves the directory. A file "a..b" does not.
        data = self._validate_file_export({"patterns": ["/var/log/a..b.log"]})
        self.assertEqual(data["patterns"], ["/var/log/a..b.log"])

    def test_file_export_no_patterns(self):
        with self.assertRaises(serializers.ValidationError) as cm:
            self._validate_file_export({"patterns": []})
        self.assertIn("patterns", cm.exception.detail)

    def test_file_export_too_many_patterns(self):
        with self.assertRaises(serializers.ValidationError) as cm:
            self._validate_file_export({"patterns": [f"/tmp/{i}" for i in range(MAX_PATTERNS + 1)]})
        self.assertIn("patterns", cm.exception.detail)

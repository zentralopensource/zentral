from django.contrib.auth.models import Permission
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from pbac.engine import engine
from zentral.contrib.turbo.command_backends import CommandBackend
from zentral.contrib.turbo.models import Command, FileExport, Job, Sysdiagnose
from zentral.core.events.base import linked_objects_key
from .utils import force_command, force_mscp_check, force_script


class TurboCommandKindsTestCase(TestCase):
    # Sysdiagnose and FileExport share the Command table. Nothing an operator sees names the table.

    # loading

    def test_a_row_loads_as_its_kind(self):
        sysdiagnose = force_command(backend=CommandBackend.SYSDIAGNOSE)
        file_export = force_command(backend=CommandBackend.FILE_EXPORT)
        self.assertIs(type(Command.objects.get(pk=sysdiagnose.pk)), Sysdiagnose)
        self.assertIs(type(Command.objects.get(pk=file_export.pk)), FileExport)

    def test_job_definition_is_the_kind(self):
        file_export = force_command(backend=CommandBackend.FILE_EXPORT)
        self.assertIs(type(Job.objects.get(pk=file_export.job_id).definition), FileExport)
        job = Job.objects.select_related(*Job.definition_relations()).get(pk=file_export.job_id)
        self.assertIs(type(job.definition), FileExport)

    def test_an_unknown_backend_stays_a_command(self):
        # a row written by a newer release, during a rolling upgrade
        command = force_command()
        Command.objects.filter(pk=command.pk).update(backend="os_log")
        self.assertIs(type(Command.objects.get(pk=command.pk)), Command)

    def test_a_row_loaded_without_its_backend_stays_a_command(self):
        command = force_command()
        self.assertIs(type(Command.objects.only("name").get(pk=command.pk)), Command)

    def test_the_kind_manager_filters_on_the_backend(self):
        sysdiagnose = force_command(backend=CommandBackend.SYSDIAGNOSE)
        file_export = force_command(backend=CommandBackend.FILE_EXPORT)
        self.assertEqual(list(Sysdiagnose.objects.all()), [sysdiagnose])
        self.assertEqual(list(FileExport.objects.all()), [file_export])

    # saving

    def test_the_kind_sets_the_backend(self):
        file_export = FileExport(name=get_random_string(12), backend=CommandBackend.SYSDIAGNOSE)
        file_export.save()
        self.assertEqual(file_export.backend, "file_export")
        self.assertEqual(file_export.job.kind, "file_export")

    def test_a_name_is_unique_for_each_kind(self):
        name = get_random_string(12)
        force_command(backend=CommandBackend.SYSDIAGNOSE, name=name)
        force_command(backend=CommandBackend.FILE_EXPORT, name=name)
        with self.assertRaises(IntegrityError), transaction.atomic():
            force_command(backend=CommandBackend.FILE_EXPORT, name=name)

    # identity

    def test_get_absolute_url(self):
        sysdiagnose = force_command(backend=CommandBackend.SYSDIAGNOSE)
        file_export = force_command(backend=CommandBackend.FILE_EXPORT)
        self.assertEqual(sysdiagnose.get_absolute_url(), reverse("turbo:sysdiagnose", args=(sysdiagnose.pk,)))
        self.assertEqual(file_export.get_absolute_url(), reverse("turbo:file_export", args=(file_export.pk,)))

    def test_serialize_for_event_keys_only(self):
        sysdiagnose = force_command()
        self.assertEqual(sysdiagnose.serialize_for_event(keys_only=True),
                         {"pk": str(sysdiagnose.pk), "name": sysdiagnose.name})

    def test_serialize_for_event_description(self):
        sysdiagnose = force_command()
        sysdiagnose.description = "Support"
        self.assertEqual(sysdiagnose.serialize_for_event()["description"], "Support")

    def test_every_kind_has_one_event_key(self):
        # The definition block of a machine event is under the kind, and its linked object key is
        # the audit key of the definition model. One key then finds every event of a definition.
        jobs = [force_script().job, force_mscp_check().job]
        jobs.extend(force_command(backend=backend).job for backend in CommandBackend.values)
        self.assertEqual(sorted(job.kind for job in jobs), sorted(Job.Kind.values))
        for job in jobs:
            job = Job.objects.get(pk=job.pk)
            payload_key, ref = job.definition_wire_ref()
            self.assertEqual(payload_key, job.kind)
            self.assertEqual(ref["pk"], str(job.definition.pk))
            self.assertEqual(job.definition_linked_objects_keys(),
                             {linked_objects_key(job.definition): [(job.definition.pk,)]})

    # authorization

    def test_permissions_for_each_kind(self):
        codenames = set(Permission.objects.filter(content_type__app_label="turbo")
                                          .values_list("codename", flat=True))
        for model_name in ("sysdiagnose", "fileexport"):
            for operation in ("add", "change", "delete", "view"):
                self.assertIn(f"{operation}_{model_name}", codenames)
        self.assertEqual([codename for codename in codenames if codename.endswith("_command")], [])

    def test_pbac_actions_for_each_kind(self):
        for object_name in ("Sysdiagnose", "FileExport"):
            for operation in ("create", "update", "delete", "view"):
                self.assertIn((f"{operation}{object_name}", "Turbo"), engine.actions)
        self.assertEqual([key for key in engine.actions if key[1] == "Turbo" and "Command" in key[0]], [])

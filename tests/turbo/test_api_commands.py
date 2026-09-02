from unittest.mock import patch
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.turbo.command_backends import CommandBackend
from zentral.contrib.turbo.command_backends.file_export import DEFAULT_MAX_SIZE
from zentral.contrib.turbo.models import Command, Job
from .utils import TurboAPITestCase, force_command, force_configuration, force_one_time_job


class TurboCommandAPITestCase(TurboAPITestCase):
    # create

    def test_create_sysdiagnose_without_kwargs(self):
        # a zero-config kind has no options to send, so an absent kwargs block is its normal case
        self.set_permissions("turbo.add_command")
        name = get_random_string(12)
        response = self.post(reverse("turbo_api:commands"), {"backend": "sysdiagnose", "name": name})
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertEqual(data["version"], 1)
        command = Command.objects.get(pk=data["id"])
        self.assertEqual(command.backend, "sysdiagnose")
        # the Job is minted with kind == backend: the two are one wire identity
        self.assertEqual(command.job.kind, "sysdiagnose")
        self.assertEqual(data["job_id"], str(command.job_id))
        self.assertEqual(command.get_backend_kwargs(), {})

    def test_create_file_export(self):
        self.set_permissions("turbo.add_command")
        response = self.post(reverse("turbo_api:commands"),
                             {"backend": "file_export", "name": get_random_string(12),
                              "file_export_kwargs": {"patterns": ["/var/log/install.log*"]}})
        self.assertEqual(response.status_code, 201)
        command = Command.objects.get(pk=response.json()["id"])
        self.assertEqual(command.job.kind, "file_export")
        self.assertEqual(command.get_backend_kwargs(),
                         {"patterns": ["/var/log/install.log*"], "max_size": DEFAULT_MAX_SIZE})

    def test_create_file_export_without_kwargs(self):
        self.set_permissions("turbo.add_command")
        response = self.post(reverse("turbo_api:commands"),
                             {"backend": "file_export", "name": get_random_string(12)})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"file_export_kwargs": ["This field is required."]})

    def test_create_command_ignores_another_backends_kwargs(self):
        # a client that sends the wrong block gets the command it asked for, with that block dropped —
        # the backend decides which kwargs are its own
        self.set_permissions("turbo.add_command")
        response = self.post(reverse("turbo_api:commands"),
                             {"backend": "sysdiagnose", "name": get_random_string(12),
                              "file_export_kwargs": {"patterns": ["/tmp/a.log"]}})
        self.assertEqual(response.status_code, 201)
        command = Command.objects.get(pk=response.json()["id"])
        self.assertEqual(command.backend, "sysdiagnose")
        self.assertEqual(command.get_backend_kwargs(), {})

    def test_create_file_export_relative_pattern(self):
        self.set_permissions("turbo.add_command")
        response = self.post(reverse("turbo_api:commands"),
                             {"backend": "file_export", "name": get_random_string(12),
                              "file_export_kwargs": {"patterns": ["var/log/install.log"]}})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(),
                         {"file_export_kwargs": {"patterns": {"0": ["Must be an absolute path"]}}})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_command_audit_event(self, post_event):
        self.set_permissions("turbo.add_command")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.post(reverse("turbo_api:commands"),
                                 {"backend": "sysdiagnose", "name": get_random_string(12)})
        self.assertEqual(response.status_code, 201)
        command = Command.objects.get(pk=response.json()["id"])
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        payload_object = audit_events[0].payload["object"]
        self.assertEqual(payload_object["model"], "turbo.command")
        # the backend rides the audit event for free — per-kind authorization is written against it
        self.assertEqual(payload_object["new_value"]["backend"], "sysdiagnose")
        self.assertEqual(audit_events[0].metadata.serialize()["objects"],
                         {"turbo_command": [str(command.pk)]})

    # read

    def test_list_commands(self):
        command = force_command()
        self.set_permissions("turbo.view_command")
        response = self.get(reverse("turbo_api:commands"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["results"][0]["id"], str(command.pk))

    def test_list_commands_backend_filter(self):
        force_command(backend=CommandBackend.SYSDIAGNOSE)
        file_export = force_command(backend=CommandBackend.FILE_EXPORT)
        self.set_permissions("turbo.view_command")
        response = self.get(reverse("turbo_api:commands") + "?backend=file_export")
        self.assertEqual(response.status_code, 200)
        results = response.json()["results"]
        self.assertEqual([r["id"] for r in results], [str(file_export.pk)])

    def test_list_commands_configuration_filter(self):
        configuration = force_configuration()
        scheduled = force_command()
        force_one_time_job(configuration=configuration, job=scheduled.job)
        force_command()
        self.set_permissions("turbo.view_command")
        response = self.get(reverse("turbo_api:commands") + f"?configuration={configuration.pk}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([r["id"] for r in response.json()["results"]], [str(scheduled.pk)])

    def test_get_command_unauthorized(self):
        command = force_command()
        response = self.get(reverse("turbo_api:command", args=(command.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_file_export_command(self):
        command = force_command(backend=CommandBackend.FILE_EXPORT,
                                backend_kwargs={"patterns": ["/tmp/a.log"], "max_size": 1024})
        self.set_permissions("turbo.view_command")
        response = self.get(reverse("turbo_api:command", args=(command.pk,)))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["file_export_kwargs"], {"patterns": ["/tmp/a.log"], "max_size": 1024})
        self.assertIsNone(data["sysdiagnose_kwargs"])

    # update

    def test_update_command_kwargs_bumps_the_version(self):
        # the version lives on the Job and drives a re-run, so it moves when what the agent would do
        # moves
        command = force_command(backend=CommandBackend.FILE_EXPORT,
                                backend_kwargs={"patterns": ["/tmp/a.log"], "max_size": 1024})
        self.set_permissions("turbo.change_command")
        response = self.put(reverse("turbo_api:command", args=(command.pk,)),
                            {"backend": "file_export", "name": command.name,
                             "file_export_kwargs": {"patterns": ["/tmp/b.log"], "max_size": 1024}})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["version"], 2)
        command.refresh_from_db()
        self.assertEqual(command.get_backend_kwargs()["patterns"], ["/tmp/b.log"])

    def test_update_command_name_only_keeps_the_version(self):
        # a rename changes nothing the agent would do, so it must not force a re-run
        command = force_command(backend=CommandBackend.FILE_EXPORT,
                                backend_kwargs={"patterns": ["/tmp/a.log"], "max_size": 1024})
        self.set_permissions("turbo.change_command")
        response = self.put(reverse("turbo_api:command", args=(command.pk,)),
                            {"backend": "file_export", "name": get_random_string(12),
                             "file_export_kwargs": {"patterns": ["/tmp/a.log"], "max_size": 1024}})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["version"], 1)

    def test_update_command_backend_immutable(self):
        # the backend is the kind, and the kind is half the wire identity: changing it would change what
        # the agent runs under a stable pk and version
        command = force_command(backend=CommandBackend.SYSDIAGNOSE)
        self.set_permissions("turbo.change_command")
        response = self.put(reverse("turbo_api:command", args=(command.pk,)),
                            {"backend": "file_export", "name": command.name,
                             "file_export_kwargs": {"patterns": ["/tmp/a.log"]}})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"backend": ["This field cannot be changed"]})
        command.refresh_from_db()
        self.assertEqual(command.backend, "sysdiagnose")
        self.assertEqual(command.job.kind, "sysdiagnose")

    # delete

    def test_delete_command(self):
        command = force_command()
        job_pk = command.job_id
        self.set_permissions("turbo.delete_command")
        response = self.delete(reverse("turbo_api:command", args=(command.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertFalse(Command.objects.filter(pk=command.pk).exists())
        # the Job goes with it, like a Script's
        self.assertFalse(Job.objects.filter(pk=job_pk).exists())

    def test_delete_scheduled_command(self):
        command = force_command()
        force_one_time_job(job=command.job)
        self.set_permissions("turbo.delete_command")
        response = self.delete(reverse("turbo_api:command", args=(command.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ["This command cannot be deleted"])
        self.assertTrue(Command.objects.filter(pk=command.pk).exists())

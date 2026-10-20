from unittest.mock import patch
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.turbo.command_backends import CommandBackend
from zentral.contrib.turbo.command_backends.file_export import DEFAULT_MAX_SIZE
from zentral.contrib.turbo.models import FileExport
from .utils import TurboAPITestCase, force_command, force_one_time_job


class TurboFileExportAPITestCase(TurboAPITestCase):
    maxDiff = None

    def _force_file_export(self, patterns=None, max_size=1024):
        return force_command(backend=CommandBackend.FILE_EXPORT,
                             backend_kwargs={"patterns": patterns or ["/tmp/a.log"], "max_size": max_size})

    def _expected(self, file_export):
        kwargs = file_export.get_backend_kwargs()
        return {
            "id": str(file_export.pk),
            "name": file_export.name,
            "description": file_export.description,
            "patterns": kwargs["patterns"],
            "max_size": kwargs["max_size"],
            "version": file_export.job.version,
            "job_id": str(file_export.job_id),
            "created_at": file_export.created_at.isoformat(),
            "updated_at": file_export.updated_at.isoformat(),
        }

    # create

    def test_create_file_export_unauthorized(self):
        response = self.post(reverse("turbo_api:file_exports"),
                             {"name": get_random_string(12), "patterns": ["/var/log/install.log*"]})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_file_export(self, post_event):
        self.set_permissions("turbo.add_fileexport")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True):
            response = self.post(reverse("turbo_api:file_exports"),
                                 {"name": name, "patterns": ["/var/log/install.log*"]})
        self.assertEqual(response.status_code, 201)
        file_export = FileExport.objects.get(name=name)
        self.assertEqual(response.json(), self._expected(file_export))
        self.assertEqual(file_export.job.kind, "file_export")
        self.assertEqual(file_export.get_backend_kwargs(),
                         {"patterns": ["/var/log/install.log*"], "max_size": DEFAULT_MAX_SIZE})
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        event = audit_events[0]
        self.assertEqual(
            event.payload["object"],
            {"model": "turbo.fileexport",
             "pk": str(file_export.pk),
             "new_value": {"pk": str(file_export.pk),
                           "name": name,
                           "patterns": ["/var/log/install.log*"],
                           "max_size": DEFAULT_MAX_SIZE,
                           "version": 1,
                           "created_at": file_export.created_at.isoformat(),
                           "updated_at": file_export.updated_at.isoformat()}},
        )
        self.assertEqual(event.metadata.serialize()["objects"], {"turbo_file_export": [str(file_export.pk)]})

    def test_create_file_export_without_patterns(self):
        self.set_permissions("turbo.add_fileexport")
        response = self.post(reverse("turbo_api:file_exports"), {"name": get_random_string(12)})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"patterns": ["This field is required."]})

    def test_create_file_export_relative_pattern(self):
        self.set_permissions("turbo.add_fileexport")
        response = self.post(reverse("turbo_api:file_exports"),
                             {"name": get_random_string(12), "patterns": ["var/log/install.log"]})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"patterns": {"0": ["Must be an absolute path"]}})

    def test_create_file_export_name_conflict(self):
        file_export = self._force_file_export()
        self.set_permissions("turbo.add_fileexport")
        response = self.post(reverse("turbo_api:file_exports"),
                             {"name": file_export.name, "patterns": ["/tmp/b.log"]})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"name": ["file export with this name already exists."]})

    # list

    def test_list_file_exports(self):
        file_export = self._force_file_export()
        force_command(backend=CommandBackend.SYSDIAGNOSE)
        self.set_permissions("turbo.view_fileexport")
        response = self.get(reverse("turbo_api:file_exports"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["results"], [self._expected(file_export)])

    # get

    def test_get_file_export_unauthorized(self):
        file_export = self._force_file_export()
        self.set_permissions("turbo.view_sysdiagnose")
        response = self.get(reverse("turbo_api:file_export", args=(file_export.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_file_export(self):
        file_export = self._force_file_export(patterns=["/tmp/a.log", "/tmp/b/*.log"], max_size=2048)
        self.set_permissions("turbo.view_fileexport")
        response = self.get(reverse("turbo_api:file_export", args=(file_export.pk,)))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data, self._expected(file_export))
        self.assertEqual(data["patterns"], ["/tmp/a.log", "/tmp/b/*.log"])
        self.assertEqual(data["max_size"], 2048)

    # update

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_file_export_options_bump_the_version(self, post_event):
        # The version is on the Job. It changes when the work of the agent changes.
        file_export = self._force_file_export()
        self.set_permissions("turbo.change_fileexport")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.put(reverse("turbo_api:file_export", args=(file_export.pk,)),
                                {"name": file_export.name, "patterns": ["/tmp/b.log"], "max_size": 1024})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["version"], 2)
        file_export.refresh_from_db()
        self.assertEqual(file_export.get_backend_kwargs(), {"patterns": ["/tmp/b.log"], "max_size": 1024})
        event = self._audit_events(post_event)[0]
        self.assertEqual(event.payload["object"]["prev_value"]["patterns"], ["/tmp/a.log"])
        self.assertEqual(event.payload["object"]["new_value"]["patterns"], ["/tmp/b.log"])
        self.assertEqual(event.payload["object"]["new_value"]["version"], 2)

    def test_update_file_export_default_max_size(self):
        # an update replaces every option, so an absent max_size is the default again
        file_export = self._force_file_export()
        self.set_permissions("turbo.change_fileexport")
        response = self.put(reverse("turbo_api:file_export", args=(file_export.pk,)),
                            {"name": file_export.name, "patterns": ["/tmp/a.log"]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["max_size"], DEFAULT_MAX_SIZE)
        self.assertEqual(response.json()["version"], 2)

    def test_update_file_export_name_only_keeps_the_version(self):
        # a new name does not change the work of the agent, so it must not start a new run
        file_export = self._force_file_export()
        self.set_permissions("turbo.change_fileexport")
        response = self.put(reverse("turbo_api:file_export", args=(file_export.pk,)),
                            {"name": get_random_string(12), "patterns": ["/tmp/a.log"], "max_size": 1024})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["version"], 1)

    def test_update_file_export_without_patterns(self):
        file_export = self._force_file_export()
        self.set_permissions("turbo.change_fileexport")
        response = self.put(reverse("turbo_api:file_export", args=(file_export.pk,)), {"name": file_export.name})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"patterns": ["This field is required."]})

    # delete

    def test_delete_file_export(self):
        file_export = self._force_file_export()
        self.set_permissions("turbo.delete_fileexport")
        response = self.delete(reverse("turbo_api:file_export", args=(file_export.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertFalse(FileExport.objects.filter(pk=file_export.pk).exists())

    def test_delete_scheduled_file_export(self):
        file_export = self._force_file_export()
        force_one_time_job(job=file_export.job)
        self.set_permissions("turbo.delete_fileexport")
        response = self.delete(reverse("turbo_api:file_export", args=(file_export.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ["This file export cannot be deleted"])

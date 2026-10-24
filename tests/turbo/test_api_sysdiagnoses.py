from unittest.mock import patch
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.turbo.command_backends import CommandBackend
from zentral.contrib.turbo.models import Job, Sysdiagnose
from .utils import (VIEW_ONE_TIME_JOB_ACTION, VIEW_RECURRING_JOB_ACTION, TurboAPITestCase, force_command,
                    force_configuration, force_one_time_job, turbo_policy)


class TurboSysdiagnoseAPITestCase(TurboAPITestCase):
    maxDiff = None

    def _expected(self, sysdiagnose):
        return {
            "id": str(sysdiagnose.pk),
            "name": sysdiagnose.name,
            "description": sysdiagnose.description,
            "version": sysdiagnose.job.version,
            "job_id": str(sysdiagnose.job_id),
            "created_at": sysdiagnose.created_at.isoformat(),
            "updated_at": sysdiagnose.updated_at.isoformat(),
        }

    # create

    def test_create_sysdiagnose_unauthorized(self):
        response = self.post(reverse("turbo_api:sysdiagnoses"), {"name": get_random_string(12)})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_sysdiagnose(self, post_event):
        self.set_permissions("turbo.add_sysdiagnose")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True):
            response = self.post(reverse("turbo_api:sysdiagnoses"), {"name": name})
        self.assertEqual(response.status_code, 201)
        sysdiagnose = Sysdiagnose.objects.get(name=name)
        self.assertEqual(response.json(), self._expected(sysdiagnose))
        self.assertEqual(sysdiagnose.job.kind, "sysdiagnose")
        self.assertEqual(sysdiagnose.get_backend_kwargs(), {})
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        event = audit_events[0]
        self.assertEqual(
            event.payload["object"],
            {"model": "turbo.sysdiagnose",
             "pk": str(sysdiagnose.pk),
             "new_value": {"pk": str(sysdiagnose.pk),
                           "name": name,
                           "version": 1,
                           "created_at": sysdiagnose.created_at.isoformat(),
                           "updated_at": sysdiagnose.updated_at.isoformat()}},
        )
        self.assertEqual(event.metadata.serialize()["objects"], {"turbo_sysdiagnose": [str(sysdiagnose.pk)]})

    def test_create_sysdiagnose_ignores_the_fields_of_another_kind(self):
        # the endpoint decides the kind: a backend or an option in the body changes nothing
        self.set_permissions("turbo.add_sysdiagnose")
        response = self.post(reverse("turbo_api:sysdiagnoses"),
                             {"name": get_random_string(12), "backend": "file_export", "patterns": ["/tmp/a.log"]})
        self.assertEqual(response.status_code, 201)
        sysdiagnose = Sysdiagnose.objects.get(pk=response.json()["id"])
        self.assertEqual(sysdiagnose.backend, "sysdiagnose")
        self.assertEqual(sysdiagnose.get_backend_kwargs(), {})

    def test_create_sysdiagnose_name_conflict(self):
        sysdiagnose = force_command()
        self.set_permissions("turbo.add_sysdiagnose")
        response = self.post(reverse("turbo_api:sysdiagnoses"), {"name": sysdiagnose.name})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"name": ["sysdiagnose with this name already exists."]})

    def test_create_sysdiagnose_with_the_name_of_a_file_export(self):
        # a name is unique for each kind, like the name of a script
        file_export = force_command(backend=CommandBackend.FILE_EXPORT)
        self.set_permissions("turbo.add_sysdiagnose")
        response = self.post(reverse("turbo_api:sysdiagnoses"), {"name": file_export.name})
        self.assertEqual(response.status_code, 201)

    # list

    def test_list_sysdiagnoses_unauthorized(self):
        response = self.get(reverse("turbo_api:sysdiagnoses"))
        self.assertEqual(response.status_code, 403)

    def test_list_sysdiagnoses(self):
        sysdiagnose = force_command()
        force_command(backend=CommandBackend.FILE_EXPORT)
        self.set_permissions("turbo.view_sysdiagnose")
        response = self.get(reverse("turbo_api:sysdiagnoses"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["results"], [self._expected(sysdiagnose)])

    def test_list_sysdiagnoses_name_filter(self):
        sysdiagnose = force_command()
        force_command()
        self.set_permissions("turbo.view_sysdiagnose")
        response = self.get(reverse("turbo_api:sysdiagnoses") + f"?name={sysdiagnose.name}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([r["id"] for r in response.json()["results"]], [str(sysdiagnose.pk)])

    def test_list_sysdiagnoses_configuration_filter(self):
        configuration = force_configuration()
        scheduled = force_command()
        force_one_time_job(configuration=configuration, job=scheduled.job)
        force_command()
        self.set_policy(turbo_policy(self.group, "turbo.view_sysdiagnose",
                                                 actions=(VIEW_ONE_TIME_JOB_ACTION, VIEW_RECURRING_JOB_ACTION)))
        response = self.get(reverse("turbo_api:sysdiagnoses") + f"?configuration={configuration.pk}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([r["id"] for r in response.json()["results"]], [str(scheduled.pk)])

    # get

    def test_get_sysdiagnose_unauthorized(self):
        sysdiagnose = force_command()
        response = self.get(reverse("turbo_api:sysdiagnose", args=(sysdiagnose.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_sysdiagnose(self):
        sysdiagnose = force_command()
        self.set_permissions("turbo.view_sysdiagnose")
        response = self.get(reverse("turbo_api:sysdiagnose", args=(sysdiagnose.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), self._expected(sysdiagnose))

    def test_get_file_export_as_sysdiagnose_not_found(self):
        file_export = force_command(backend=CommandBackend.FILE_EXPORT)
        self.set_permissions("turbo.view_sysdiagnose")
        response = self.get(reverse("turbo_api:sysdiagnose", args=(file_export.pk,)))
        self.assertEqual(response.status_code, 404)

    # update

    def test_update_sysdiagnose_keeps_the_version(self):
        # nothing that the agent runs changes, so the update must not start a new run
        sysdiagnose = force_command()
        self.set_permissions("turbo.change_sysdiagnose")
        new_name = get_random_string(12)
        response = self.put(reverse("turbo_api:sysdiagnose", args=(sysdiagnose.pk,)),
                            {"name": new_name, "description": "Support"})
        self.assertEqual(response.status_code, 200)
        sysdiagnose.refresh_from_db()
        self.assertEqual(sysdiagnose.name, new_name)
        self.assertEqual(sysdiagnose.description, "Support")
        self.assertEqual(response.json(), self._expected(sysdiagnose))
        self.assertEqual(response.json()["version"], 1)

    def test_update_sysdiagnose_name_conflict(self):
        sysdiagnose = force_command()
        other = force_command()
        self.set_permissions("turbo.change_sysdiagnose")
        response = self.put(reverse("turbo_api:sysdiagnose", args=(sysdiagnose.pk,)), {"name": other.name})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"name": ["sysdiagnose with this name already exists."]})

    # delete

    def test_delete_sysdiagnose_unauthorized(self):
        sysdiagnose = force_command()
        response = self.delete(reverse("turbo_api:sysdiagnose", args=(sysdiagnose.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_sysdiagnose(self):
        sysdiagnose = force_command()
        job_pk = sysdiagnose.job_id
        self.set_permissions("turbo.delete_sysdiagnose")
        response = self.delete(reverse("turbo_api:sysdiagnose", args=(sysdiagnose.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertFalse(Sysdiagnose.objects.filter(pk=sysdiagnose.pk).exists())
        # the delete removes the Job too, like a Script
        self.assertFalse(Job.objects.filter(pk=job_pk).exists())

    def test_delete_scheduled_sysdiagnose(self):
        sysdiagnose = force_command()
        force_one_time_job(job=sysdiagnose.job)
        self.set_permissions("turbo.delete_sysdiagnose")
        response = self.delete(reverse("turbo_api:sysdiagnose", args=(sysdiagnose.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ["This sysdiagnose cannot be deleted"])
        self.assertTrue(Sysdiagnose.objects.filter(pk=sysdiagnose.pk).exists())

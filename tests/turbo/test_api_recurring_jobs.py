from unittest.mock import patch
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import Tag
from zentral.contrib.turbo.models import RecurringJob
from .utils import (TurboAPITestCase, force_command, force_configuration, force_recurring_job,
                    force_script)


class TurboRecurringJobAPITestCase(TurboAPITestCase):
    def test_create_recurring_job_unauthorized(self):
        configuration = force_configuration()
        script = force_script()
        response = self.post(reverse("turbo_api:recurring_jobs"),
                             {"configuration": str(configuration.pk), "job": str(script.job.pk)},
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_recurring_job_permission_denied(self):
        configuration = force_configuration()
        script = force_script()
        response = self.post(reverse("turbo_api:recurring_jobs"),
                             {"configuration": str(configuration.pk), "job": str(script.job.pk)})
        self.assertEqual(response.status_code, 403)

    def test_create_recurring_command_rejected(self):
        # a command kind declares itself one-time only: a recurring collection is a log shipper, not a
        # job. The GUI narrows its choices instead; the API has to say so.
        configuration = force_configuration()
        command = force_command()
        self.set_permissions("turbo.add_recurringjob")
        response = self.post(reverse("turbo_api:recurring_jobs"),
                             {"configuration": str(configuration.pk), "job": str(command.job.pk),
                              "interval": 3600})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(),
                         {"job": ["A sysdiagnose job cannot be scheduled to run repeatedly"]})
        self.assertFalse(RecurringJob.objects.filter(job=command.job).exists())

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_recurring_job(self, post_event):
        configuration = force_configuration()
        script = force_script()
        self.set_permissions("turbo.add_recurringjob")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.post(reverse("turbo_api:recurring_jobs"),
                                 {"configuration": str(configuration.pk), "job": str(script.job.pk),
                                  "interval": 3600})
        self.assertEqual(response.status_code, 201)
        recurring_job = RecurringJob.objects.get(pk=response.json()["id"])
        self.assertEqual(recurring_job.configuration, configuration)
        self.assertEqual(recurring_job.job, script.job)
        self.assertEqual(recurring_job.interval, 3600)
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        self.assertEqual(audit_events[0].payload["action"], "created")
        self.assertEqual(audit_events[0].payload["object"]["model"], "turbo.recurringjob")
        metadata = audit_events[0].metadata.serialize()
        self.assertEqual(set(metadata["objects"]),
                         {"turbo_recurring_job", "turbo_configuration", "turbo_script"})
        self.assertEqual(metadata["objects"]["turbo_recurring_job"], [str(recurring_job.pk)])
        self.assertEqual(metadata["objects"]["turbo_configuration"], [str(configuration.pk)])
        self.assertEqual(metadata["objects"]["turbo_script"], [str(script.pk)])

    def test_create_recurring_job_with_scope(self):
        configuration = force_configuration()
        script = force_script()
        tag = Tag.objects.create(name=get_random_string(12))
        self.set_permissions("turbo.add_recurringjob")
        response = self.post(reverse("turbo_api:recurring_jobs"),
                             {"configuration": str(configuration.pk), "job": str(script.job.pk),
                              "tags": [tag.pk], "serial_numbers": ["ABC123", "DEF456"]})
        self.assertEqual(response.status_code, 201)
        recurring_job = RecurringJob.objects.get(pk=response.json()["id"])
        self.assertEqual(list(recurring_job.tags.all()), [tag])
        self.assertEqual(recurring_job.serial_numbers, ["ABC123", "DEF456"])

    def test_create_recurring_job_duplicate(self):
        recurring_job = force_recurring_job()
        self.set_permissions("turbo.add_recurringjob")
        response = self.post(reverse("turbo_api:recurring_jobs"),
                             {"configuration": str(recurring_job.configuration.pk),
                              "job": str(recurring_job.job.pk)})
        self.assertEqual(response.status_code, 400)

    def test_create_recurring_job_disjoint_tags(self):
        configuration = force_configuration()
        script = force_script()
        tag = Tag.objects.create(name=get_random_string(12))
        self.set_permissions("turbo.add_recurringjob")
        response = self.post(reverse("turbo_api:recurring_jobs"),
                             {"configuration": str(configuration.pk), "job": str(script.job.pk),
                              "tags": [tag.pk], "excluded_tags": [tag.pk]})
        self.assertEqual(response.status_code, 400)

    def test_list_recurring_jobs(self):
        # creation order — LimitOffset pagination over an unordered queryset returns unstable pages
        recurring_jobs = [force_recurring_job() for _ in range(2)]
        self.set_permissions("turbo.view_recurringjob")
        response = self.get(reverse("turbo_api:recurring_jobs"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 2)
        self.assertEqual([j["id"] for j in response.json()["results"]],
                         [str(j.pk) for j in recurring_jobs])

    def test_list_recurring_jobs_constant_query_count(self):
        # the serializer renders tags/excluded_tags; the list queryset prefetches them → no per-row N+1
        self.set_permissions("turbo.view_recurringjob")
        force_recurring_job()
        self.get(reverse("turbo_api:recurring_jobs"))  # warm process-level caches
        with CaptureQueriesContext(connection) as one:
            self.assertEqual(self.get(reverse("turbo_api:recurring_jobs")).status_code, 200)
        for _ in range(4):
            force_recurring_job()
        with CaptureQueriesContext(connection) as five:
            self.assertEqual(self.get(reverse("turbo_api:recurring_jobs")).status_code, 200)
        self.assertEqual(len(one.captured_queries), len(five.captured_queries))

    def test_list_recurring_jobs_filter_by_configuration(self):
        recurring_job = force_recurring_job()
        force_recurring_job()
        self.set_permissions("turbo.view_recurringjob")
        response = self.get(reverse("turbo_api:recurring_jobs"),
                            {"configuration": str(recurring_job.configuration.pk)})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["results"][0]["id"], str(recurring_job.pk))

    def test_get_recurring_job(self):
        recurring_job = force_recurring_job(interval=3600)
        self.set_permissions("turbo.view_recurringjob")
        response = self.get(reverse("turbo_api:recurring_job", args=(recurring_job.pk,)))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["id"], str(recurring_job.pk))
        self.assertEqual(data["interval"], 3600)

    def test_update_recurring_job(self):
        recurring_job = force_recurring_job(interval=3600)
        self.set_permissions("turbo.change_recurringjob")
        response = self.put(reverse("turbo_api:recurring_job", args=(recurring_job.pk,)),
                            {"configuration": str(recurring_job.configuration.pk),
                             "job": str(recurring_job.job.pk), "interval": 7200})
        self.assertEqual(response.status_code, 200)
        recurring_job.refresh_from_db()
        self.assertEqual(recurring_job.interval, 7200)

    def test_update_recurring_job_configuration_immutable(self):
        # re-pointing a schedule to another configuration would retarget that config's whole fleet
        recurring_job = force_recurring_job(interval=3600)
        other_configuration = force_configuration()
        self.set_permissions("turbo.change_recurringjob")
        response = self.put(reverse("turbo_api:recurring_job", args=(recurring_job.pk,)),
                            {"configuration": str(other_configuration.pk),
                             "job": str(recurring_job.job.pk), "interval": 7200})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"configuration": ["This field cannot be changed"]})
        recurring_job.refresh_from_db()
        self.assertEqual(recurring_job.interval, 3600)

    def test_update_recurring_job_job_immutable(self):
        # re-pointing a schedule to another job would strand its per-machine ledger rows
        recurring_job = force_recurring_job(interval=3600)
        other_script = force_script()
        self.set_permissions("turbo.change_recurringjob")
        response = self.put(reverse("turbo_api:recurring_job", args=(recurring_job.pk,)),
                            {"configuration": str(recurring_job.configuration.pk),
                             "job": str(other_script.job.pk), "interval": 7200})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"job": ["This field cannot be changed"]})
        recurring_job.refresh_from_db()
        self.assertEqual(recurring_job.interval, 3600)

    def test_delete_recurring_job(self):
        recurring_job = force_recurring_job()
        pk = recurring_job.pk
        self.set_permissions("turbo.delete_recurringjob")
        response = self.delete(reverse("turbo_api:recurring_job", args=(pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertFalse(RecurringJob.objects.filter(pk=pk).exists())

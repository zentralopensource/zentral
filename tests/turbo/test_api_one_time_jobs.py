from unittest.mock import patch
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from zentral.contrib.turbo.models import OneTimeJob
from .utils import TurboAPITestCase, force_configuration, force_one_time_job, force_script


class TurboOneTimeJobAPITestCase(TurboAPITestCase):
    def test_create_one_time_job_unauthorized(self):
        configuration = force_configuration()
        script = force_script()
        response = self.post(reverse("turbo_api:one_time_jobs"),
                             {"configuration": str(configuration.pk), "job": str(script.job.pk)},
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_one_time_job_permission_denied(self):
        configuration = force_configuration()
        script = force_script()
        response = self.post(reverse("turbo_api:one_time_jobs"),
                             {"configuration": str(configuration.pk), "job": str(script.job.pk)})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_one_time_job(self, post_event):
        configuration = force_configuration()
        script = force_script()
        self.set_permissions("turbo.add_onetimejob")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.post(reverse("turbo_api:one_time_jobs"),
                                 {"configuration": str(configuration.pk), "job": str(script.job.pk),
                                  "not_before": "2026-07-01T10:00:00Z"})
        self.assertEqual(response.status_code, 201)
        one_time_job = OneTimeJob.objects.get(pk=response.json()["id"])
        self.assertEqual(one_time_job.configuration, configuration)
        self.assertEqual(one_time_job.job, script.job)
        self.assertIsNotNone(one_time_job.not_before)
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        self.assertEqual(audit_events[0].payload["action"], "created")
        self.assertEqual(audit_events[0].payload["object"]["model"], "turbo.onetimejob")
        metadata = audit_events[0].metadata.serialize()
        self.assertEqual(set(metadata["objects"]),
                         {"turbo_one_time_job", "turbo_configuration", "turbo_script"})
        self.assertEqual(metadata["objects"]["turbo_one_time_job"], [str(one_time_job.pk)])
        self.assertEqual(metadata["objects"]["turbo_configuration"], [str(configuration.pk)])
        self.assertEqual(metadata["objects"]["turbo_script"], [str(script.pk)])

    def test_create_one_time_job_window_validation(self):
        configuration = force_configuration()
        script = force_script()
        self.set_permissions("turbo.add_onetimejob")
        response = self.post(reverse("turbo_api:one_time_jobs"),
                             {"configuration": str(configuration.pk), "job": str(script.job.pk),
                              "not_before": "2026-07-02T10:00:00Z", "not_after": "2026-07-01T10:00:00Z"})
        self.assertEqual(response.status_code, 400)

    def test_create_one_time_job_disjoint_serial_numbers(self):
        configuration = force_configuration()
        script = force_script()
        self.set_permissions("turbo.add_onetimejob")
        response = self.post(reverse("turbo_api:one_time_jobs"),
                             {"configuration": str(configuration.pk), "job": str(script.job.pk),
                              "serial_numbers": ["ABC123"], "excluded_serial_numbers": ["ABC123"]})
        self.assertEqual(response.status_code, 400)

    def test_create_one_time_job_allows_duplicate(self):
        one_time_job = force_one_time_job()
        self.set_permissions("turbo.add_onetimejob")
        response = self.post(reverse("turbo_api:one_time_jobs"),
                             {"configuration": str(one_time_job.configuration.pk),
                              "job": str(one_time_job.job.pk)})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(
            OneTimeJob.objects.filter(configuration=one_time_job.configuration, job=one_time_job.job).count(),
            2,
        )

    def test_list_one_time_jobs(self):
        one_time_job = force_one_time_job()
        self.set_permissions("turbo.view_onetimejob")
        response = self.get(reverse("turbo_api:one_time_jobs"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["results"][0]["id"], str(one_time_job.pk))

    def test_list_one_time_jobs_constant_query_count(self):
        # the serializer renders tags/excluded_tags; the list queryset prefetches them → no per-row N+1
        self.set_permissions("turbo.view_onetimejob")
        force_one_time_job()
        self.get(reverse("turbo_api:one_time_jobs"))  # warm process-level caches
        with CaptureQueriesContext(connection) as one:
            self.assertEqual(self.get(reverse("turbo_api:one_time_jobs")).status_code, 200)
        for _ in range(4):
            force_one_time_job()
        with CaptureQueriesContext(connection) as five:
            self.assertEqual(self.get(reverse("turbo_api:one_time_jobs")).status_code, 200)
        self.assertEqual(len(one.captured_queries), len(five.captured_queries))

    def test_get_one_time_job(self):
        one_time_job = force_one_time_job()
        self.set_permissions("turbo.view_onetimejob")
        response = self.get(reverse("turbo_api:one_time_job", args=(one_time_job.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["id"], str(one_time_job.pk))

    def test_update_one_time_job(self):
        one_time_job = force_one_time_job()
        self.set_permissions("turbo.change_onetimejob")
        response = self.put(reverse("turbo_api:one_time_job", args=(one_time_job.pk,)),
                            {"configuration": str(one_time_job.configuration.pk),
                             "job": str(one_time_job.job.pk), "not_before": "2026-08-01T09:00:00Z"})
        self.assertEqual(response.status_code, 200)
        one_time_job.refresh_from_db()
        self.assertIsNotNone(one_time_job.not_before)

    def test_delete_one_time_job(self):
        one_time_job = force_one_time_job()
        pk = one_time_job.pk
        self.set_permissions("turbo.delete_onetimejob")
        response = self.delete(reverse("turbo_api:one_time_job", args=(pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertFalse(OneTimeJob.objects.filter(pk=pk).exists())

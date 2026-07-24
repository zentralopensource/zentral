from unittest.mock import patch
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import Tag
from zentral.contrib.turbo.models import OneTimeJob
from .utils import (TurboSetupTestCase, force_configuration, force_mscp_check,
                    force_one_time_job, force_script)


class TurboSetupOneTimeJobsTestCase(TurboSetupTestCase):
    # list

    def test_one_time_jobs_redirect(self):
        self.login_redirect("one_time_jobs")

    def test_one_time_jobs_permission_denied(self):
        self.login()
        response = self.client.get(reverse("turbo:one_time_jobs"))
        self.assertEqual(response.status_code, 403)

    def test_one_time_jobs(self):
        one_time_job = force_one_time_job()
        self.login("turbo.view_onetimejob")
        response = self.client.get(reverse("turbo:one_time_jobs"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/onetimejob_list.html")
        self.assertContains(response, str(one_time_job.job.definition))

    def test_one_time_jobs_search_by_configuration(self):
        one_time_job = force_one_time_job()
        force_one_time_job()
        self.login("turbo.view_onetimejob")
        response = self.client.get(reverse("turbo:one_time_jobs"),
                                   {"configuration": one_time_job.configuration.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["object_list"]), [one_time_job])

    def test_one_time_jobs_filter_by_kind(self):
        force_one_time_job()
        mscp_one_time_job = force_one_time_job(job=force_mscp_check().job)
        self.login("turbo.view_onetimejob")
        response = self.client.get(reverse("turbo:one_time_jobs"), {"kind": "mscp_check"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["object_list"]), [mscp_one_time_job])

    def test_one_time_jobs_search_by_q(self):
        one_time_job = force_one_time_job()
        force_one_time_job()
        self.login("turbo.view_onetimejob")
        response = self.client.get(reverse("turbo:one_time_jobs"), {"q": str(one_time_job.job.definition)})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["object_list"]), [one_time_job])

    def test_one_time_jobs_list_constant_query_count(self):
        # scope tags/excluded_tags are prefetched: more jobs must not add per-row M2M queries
        self.login("turbo.view_onetimejob")

        def list_query_count(n):
            OneTimeJob.objects.all().delete()
            for _ in range(n):
                force_one_time_job()
            with CaptureQueriesContext(connection) as ctx:
                self.assertEqual(self.client.get(reverse("turbo:one_time_jobs")).status_code, 200)
            return len(ctx.captured_queries)

        list_query_count(1)  # warm process-level caches before measuring
        self.assertEqual(list_query_count(1), list_query_count(5))

    def test_one_time_jobs_search_no_result_shows_empty_results(self):
        force_one_time_job()
        self.login("turbo.view_onetimejob")
        response = self.client.get(reverse("turbo:one_time_jobs"), {"q": get_random_string(20)})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["object_list"]), [])
        self.assertContains(response, "We didn't find any item")

    def test_one_time_jobs_empty_shows_no_entities(self):
        self.login("turbo.view_onetimejob")
        response = self.client.get(reverse("turbo:one_time_jobs"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "There are no Turbo one-time jobs created.")

    def test_one_time_jobs_pagination_reset_link(self):
        force_one_time_job()
        force_one_time_job()
        self.user.items_per_page = 1
        self.user.save()
        self.login("turbo.view_onetimejob")
        response = self.client.get(reverse("turbo:one_time_jobs"), {"page": 2})
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(response.context.get("reset_link"))
        # pagination is rendered both above and below the table
        self.assertEqual(response.content.decode("utf-8").count('aria-label="Page navigation"'), 2)

    def test_update_one_time_job_get(self):
        otj = force_one_time_job()
        self.login("turbo.change_onetimejob")
        response = self.client.get(reverse("turbo:update_one_time_job", args=(otj.configuration.pk, otj.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/onetimejob_form.html")

    def test_delete_one_time_job_get(self):
        otj = force_one_time_job()
        self.login("turbo.delete_onetimejob")
        response = self.client.get(reverse("turbo:delete_one_time_job", args=(otj.configuration.pk, otj.pk)))
        self.assertEqual(response.status_code, 200)

    # configuration preview

    def test_configuration_detail_shows_one_time_jobs(self):
        one_time_job = force_one_time_job()
        self.login("turbo.view_configuration", "turbo.view_onetimejob")
        response = self.client.get(one_time_job.configuration.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/configuration_detail.html")
        self.assertContains(response, str(one_time_job.job.definition))

    # create

    def test_create_one_time_job_redirect(self):
        configuration = force_configuration()
        response = self.client.get(reverse("turbo:create_one_time_job", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 302)

    def test_create_one_time_job_permission_denied(self):
        configuration = force_configuration()
        self.login()
        response = self.client.get(reverse("turbo:create_one_time_job", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_create_one_time_job_get(self):
        configuration = force_configuration()
        self.login("turbo.add_onetimejob")
        response = self.client.get(reverse("turbo:create_one_time_job", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/onetimejob_form.html")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_one_time_job(self, post_event):
        configuration = force_configuration()
        script = force_script()
        self.login("turbo.add_onetimejob", "turbo.view_configuration")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("turbo:create_one_time_job", args=(configuration.pk,)),
                {"job": str(script.job.pk), "not_before": "2026-07-01 10:00:00",
                 "serial_numbers": "", "excluded_serial_numbers": ""},
                follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/configuration_detail.html")
        one_time_job = OneTimeJob.objects.get(configuration=configuration, job=script.job)
        self.assertIsNotNone(one_time_job.not_before)
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        event = audit_events[0]
        self.assertEqual(event.payload["action"], "created")
        self.assertEqual(event.payload["object"]["model"], "turbo.onetimejob")
        self.assertEqual(event.payload["object"]["pk"], str(one_time_job.pk))
        metadata = event.metadata.serialize()
        self.assertEqual(set(metadata["objects"]),
                         {"turbo_one_time_job", "turbo_configuration", "turbo_script"})
        self.assertEqual(metadata["objects"]["turbo_one_time_job"], [str(one_time_job.pk)])
        self.assertEqual(metadata["objects"]["turbo_script"], [str(script.pk)])

    def test_create_one_time_job_window_validation(self):
        configuration = force_configuration()
        script = force_script()
        self.login("turbo.add_onetimejob")
        response = self.client.post(
            reverse("turbo:create_one_time_job", args=(configuration.pk,)),
            {"job": str(script.job.pk),
             "not_before": "2026-07-02 10:00:00", "not_after": "2026-07-01 10:00:00",
             "serial_numbers": "", "excluded_serial_numbers": ""},
            follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/onetimejob_form.html")
        self.assertFormError(response.context["form"], "not_after",
                             "not_after must be on or after not_before")

    def test_create_one_time_job_disjoint_tags(self):
        configuration = force_configuration()
        script = force_script()
        tag = Tag.objects.create(name=get_random_string(12))
        self.login("turbo.add_onetimejob")
        response = self.client.post(
            reverse("turbo:create_one_time_job", args=(configuration.pk,)),
            {"job": str(script.job.pk), "tags": [tag.pk], "excluded_tags": [tag.pk],
             "serial_numbers": "", "excluded_serial_numbers": ""},
            follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/onetimejob_form.html")
        self.assertFormError(response.context["form"], "excluded_tags",
                             "Tags and excluded tags must be disjoint")

    def test_create_one_time_job_allows_duplicate_job(self):
        one_time_job = force_one_time_job()
        self.login("turbo.add_onetimejob", "turbo.view_configuration")
        response = self.client.post(
            reverse("turbo:create_one_time_job", args=(one_time_job.configuration.pk,)),
            {"job": str(one_time_job.job.pk), "serial_numbers": "", "excluded_serial_numbers": ""},
            follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/configuration_detail.html")
        self.assertEqual(
            OneTimeJob.objects.filter(configuration=one_time_job.configuration, job=one_time_job.job).count(),
            2,
        )

    # update

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_one_time_job(self, post_event):
        one_time_job = force_one_time_job()
        configuration, job = one_time_job.configuration, one_time_job.job
        self.login("turbo.change_onetimejob", "turbo.view_configuration")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("turbo:update_one_time_job", args=(configuration.pk, one_time_job.pk)),
                {"job": str(job.pk), "not_before": "2026-08-01 09:00:00",
                 "serial_numbers": "", "excluded_serial_numbers": ""},
                follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/configuration_detail.html")
        one_time_job.refresh_from_db()
        self.assertIsNotNone(one_time_job.not_before)
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        self.assertEqual(audit_events[0].payload["action"], "updated")

    # delete

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_one_time_job(self, post_event):
        one_time_job = force_one_time_job()
        configuration, pk = one_time_job.configuration, one_time_job.pk
        self.login("turbo.delete_onetimejob", "turbo.view_configuration")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("turbo:delete_one_time_job", args=(configuration.pk, pk)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/configuration_detail.html")
        self.assertEqual(OneTimeJob.objects.filter(pk=pk).count(), 0)
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        self.assertEqual(audit_events[0].payload["action"], "deleted")
        self.assertEqual(audit_events[0].payload["object"]["model"], "turbo.onetimejob")

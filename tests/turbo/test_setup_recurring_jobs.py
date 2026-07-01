from unittest.mock import patch
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import Tag
from zentral.contrib.turbo.models import RecurringJob
from .utils import (TurboSetupTestCase, force_configuration, force_mscp_check,
                    force_recurring_job, force_script)


class TurboSetupRecurringJobsTestCase(TurboSetupTestCase):
    # list

    def test_recurring_jobs_redirect(self):
        self.login_redirect("recurring_jobs")

    def test_recurring_jobs_permission_denied(self):
        self.login()
        response = self.client.get(reverse("turbo:recurring_jobs"))
        self.assertEqual(response.status_code, 403)

    def test_recurring_jobs(self):
        recurring_job = force_recurring_job()
        self.login("turbo.view_recurringjob")
        response = self.client.get(reverse("turbo:recurring_jobs"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/recurringjob_list.html")
        self.assertContains(response, str(recurring_job.job.definition))

    def test_recurring_jobs_search_by_configuration(self):
        recurring_job = force_recurring_job()
        force_recurring_job()
        self.login("turbo.view_recurringjob")
        response = self.client.get(reverse("turbo:recurring_jobs"),
                                   {"configuration": recurring_job.configuration.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["object_list"]), [recurring_job])

    def test_recurring_jobs_filter_by_kind(self):
        force_recurring_job()
        mscp_recurring_job = force_recurring_job(job=force_mscp_check().job)
        self.login("turbo.view_recurringjob")
        response = self.client.get(reverse("turbo:recurring_jobs"), {"kind": "mscp_check"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["object_list"]), [mscp_recurring_job])

    def test_recurring_jobs_search_by_q(self):
        recurring_job = force_recurring_job()
        force_recurring_job()
        self.login("turbo.view_recurringjob")
        response = self.client.get(reverse("turbo:recurring_jobs"), {"q": str(recurring_job.job.definition)})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["object_list"]), [recurring_job])

    def test_recurring_jobs_list_constant_query_count(self):
        # scope tags/excluded_tags are prefetched: more jobs must not add per-row M2M queries
        self.login("turbo.view_recurringjob")

        def list_query_count(n):
            RecurringJob.objects.all().delete()
            for _ in range(n):
                force_recurring_job()
            with CaptureQueriesContext(connection) as ctx:
                self.assertEqual(self.client.get(reverse("turbo:recurring_jobs")).status_code, 200)
            return len(ctx.captured_queries)

        list_query_count(1)  # warm process-level caches before measuring
        self.assertEqual(list_query_count(1), list_query_count(5))

    def test_recurring_jobs_search_no_result_shows_empty_results(self):
        force_recurring_job()
        self.login("turbo.view_recurringjob")
        response = self.client.get(reverse("turbo:recurring_jobs"), {"q": get_random_string(20)})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["object_list"]), [])
        self.assertContains(response, "We didn't find any item")

    def test_recurring_jobs_empty_shows_no_entities(self):
        self.login("turbo.view_recurringjob")
        response = self.client.get(reverse("turbo:recurring_jobs"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "There are no Turbo recurring jobs created.")

    def test_recurring_jobs_pagination_reset_link(self):
        force_recurring_job()
        force_recurring_job()
        self.user.items_per_page = 1
        self.user.save()
        self.login("turbo.view_recurringjob")
        response = self.client.get(reverse("turbo:recurring_jobs"), {"page": 2})
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(response.context.get("reset_link"))
        # pagination is rendered both above and below the table
        self.assertEqual(response.content.decode("utf-8").count('aria-label="Page navigation"'), 2)

    def test_update_recurring_job_get(self):
        rj = force_recurring_job()
        self.login("turbo.change_recurringjob")
        response = self.client.get(reverse("turbo:update_recurring_job", args=(rj.configuration.pk, rj.pk)))
        self.assertEqual(response.status_code, 200)

    def test_delete_recurring_job_get(self):
        rj = force_recurring_job()
        self.login("turbo.delete_recurringjob")
        response = self.client.get(reverse("turbo:delete_recurring_job", args=(rj.configuration.pk, rj.pk)))
        self.assertEqual(response.status_code, 200)

    def test_create_recurring_job_disjoint_serials(self):
        configuration = force_configuration()
        job = force_script().job
        self.login("turbo.add_recurringjob")
        response = self.client.post(
            reverse("turbo:create_recurring_job", args=(configuration.pk,)),
            {"job": str(job.pk), "serial_numbers": "S1", "excluded_serial_numbers": "S1"}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response.context["form"], "excluded_serial_numbers",
                             "Serial numbers and excluded serial numbers must be disjoint")

    # configuration preview

    def test_configuration_detail_shows_recurring_jobs(self):
        recurring_job = force_recurring_job(interval=3600)
        self.login("turbo.view_configuration", "turbo.view_recurringjob")
        response = self.client.get(recurring_job.configuration.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/configuration_detail.html")
        self.assertContains(response, str(recurring_job.job.definition))

    # create

    def test_create_recurring_job_redirect(self):
        configuration = force_configuration()
        response = self.client.get(reverse("turbo:create_recurring_job", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 302)

    def test_create_recurring_job_permission_denied(self):
        configuration = force_configuration()
        self.login()
        response = self.client.get(reverse("turbo:create_recurring_job", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_create_recurring_job_get(self):
        configuration = force_configuration()
        self.login("turbo.add_recurringjob")
        response = self.client.get(reverse("turbo:create_recurring_job", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/recurringjob_form.html")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_recurring_job(self, post_event):
        configuration = force_configuration()
        script = force_script()
        self.login("turbo.add_recurringjob", "turbo.view_configuration")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("turbo:create_recurring_job", args=(configuration.pk,)),
                {"job": str(script.job.pk), "interval": 3600,
                 "serial_numbers": "", "excluded_serial_numbers": ""},
                follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/configuration_detail.html")
        recurring_job = RecurringJob.objects.get(configuration=configuration, job=script.job)
        self.assertEqual(recurring_job.interval, 3600)
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        event = audit_events[0]
        self.assertEqual(event.payload["action"], "created")
        self.assertEqual(event.payload["object"]["model"], "turbo.recurringjob")
        self.assertEqual(event.payload["object"]["pk"], str(recurring_job.pk))
        metadata = event.metadata.serialize()
        self.assertEqual(set(metadata["objects"]),
                         {"turbo_recurring_job", "turbo_configuration", "turbo_script"})
        self.assertEqual(metadata["objects"]["turbo_recurring_job"], [str(recurring_job.pk)])
        self.assertEqual(metadata["objects"]["turbo_configuration"], [str(configuration.pk)])
        self.assertEqual(metadata["objects"]["turbo_script"], [str(script.pk)])

    def test_create_recurring_job_duplicate_job_excluded(self):
        recurring_job = force_recurring_job()
        self.login("turbo.add_recurringjob")
        response = self.client.post(
            reverse("turbo:create_recurring_job", args=(recurring_job.configuration.pk,)),
            {"job": str(recurring_job.job.pk), "interval": 3600,
             "serial_numbers": "", "excluded_serial_numbers": ""},
            follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/recurringjob_form.html")
        self.assertFormError(response.context["form"], "job",
                             "Select a valid choice. That choice is not one of the available choices.")

    def test_create_recurring_job_disjoint_tags(self):
        configuration = force_configuration()
        script = force_script()
        tag = Tag.objects.create(name=get_random_string(12))
        self.login("turbo.add_recurringjob")
        response = self.client.post(
            reverse("turbo:create_recurring_job", args=(configuration.pk,)),
            {"job": str(script.job.pk), "tags": [tag.pk], "excluded_tags": [tag.pk],
             "serial_numbers": "", "excluded_serial_numbers": ""},
            follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/recurringjob_form.html")
        self.assertFormError(response.context["form"], "excluded_tags",
                             "Tags and excluded tags must be disjoint")

    # update

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_recurring_job(self, post_event):
        recurring_job = force_recurring_job(interval=3600)
        configuration, job = recurring_job.configuration, recurring_job.job
        self.login("turbo.change_recurringjob", "turbo.view_configuration")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("turbo:update_recurring_job", args=(configuration.pk, recurring_job.pk)),
                {"job": str(job.pk), "interval": 7200,
                 "serial_numbers": "", "excluded_serial_numbers": ""},
                follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/configuration_detail.html")
        recurring_job.refresh_from_db()
        self.assertEqual(recurring_job.interval, 7200)
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        self.assertEqual(audit_events[0].payload["action"], "updated")

    # delete

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_recurring_job(self, post_event):
        recurring_job = force_recurring_job()
        configuration, pk = recurring_job.configuration, recurring_job.pk
        self.login("turbo.delete_recurringjob", "turbo.view_configuration")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("turbo:delete_recurring_job", args=(configuration.pk, pk)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/configuration_detail.html")
        self.assertEqual(RecurringJob.objects.filter(pk=pk).count(), 0)
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        self.assertEqual(audit_events[0].payload["action"], "deleted")
        self.assertEqual(audit_events[0].payload["object"]["model"], "turbo.recurringjob")

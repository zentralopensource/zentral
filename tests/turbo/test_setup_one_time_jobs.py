import uuid
from unittest.mock import patch
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import Tag
from accounts.models import Policy
from zentral.contrib.turbo.command_backends import CommandBackend
from zentral.contrib.turbo.models import OneTimeJob
from .utils import (TurboSetupTestCase, forbid_job_kind_policy, force_command,
                    force_configuration, force_mscp_check, force_one_time_job, force_script,
                    turbo_policy)


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
        self.login_with_policy(turbo_policy(self.group))
        response = self.client.get(reverse("turbo:update_one_time_job", args=(otj.configuration.pk, otj.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/onetimejob_form.html")

    def test_delete_one_time_job_get(self):
        otj = force_one_time_job()
        self.login_with_policy(turbo_policy(self.group))
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

    def test_create_one_time_job_unknown_configuration_redirects_when_anonymous(self):
        # the configuration is read lazily, so nothing hits the database before the authorization
        # mixin runs: an anonymous request for a pk that does not exist gets the login redirect and
        # learns nothing about which configurations exist
        response = self.client.get(reverse("turbo:create_one_time_job", args=(uuid.uuid4(),)))
        self.assertEqual(response.status_code, 302)

    def test_create_one_time_job_permission_denied(self):
        configuration = force_configuration()
        self.login()
        response = self.client.get(reverse("turbo:create_one_time_job", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_create_one_time_job_get(self):
        configuration = force_configuration()
        self.login_with_policy(turbo_policy(self.group))
        response = self.client.get(reverse("turbo:create_one_time_job", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/onetimejob_form.html")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_one_time_job(self, post_event):
        configuration = force_configuration()
        script = force_script()
        self.login_with_policy(turbo_policy(self.group, "turbo.view_configuration"))
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
        self.login_with_policy(turbo_policy(self.group))
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
        self.login_with_policy(turbo_policy(self.group))
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
        self.login_with_policy(turbo_policy(self.group, "turbo.view_configuration"))
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
        self.login_with_policy(turbo_policy(self.group, "turbo.view_configuration"))
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

    def test_update_one_time_job_job_immutable(self):
        one_time_job = force_one_time_job()
        configuration, job = one_time_job.configuration, one_time_job.job
        other_script = force_script()
        self.login_with_policy(turbo_policy(self.group, "turbo.view_configuration"))
        response = self.client.post(
            reverse("turbo:update_one_time_job", args=(configuration.pk, one_time_job.pk)),
            {"job": str(other_script.job.pk), "not_before": "2026-08-01 09:00:00",
             "serial_numbers": "", "excluded_serial_numbers": ""})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response.context["form"], "job", "This field cannot be changed")
        one_time_job.refresh_from_db()
        self.assertEqual(one_time_job.job, job)
        self.assertIsNone(one_time_job.not_before)

    def test_update_one_time_job_without_the_disabled_job(self):
        # the browser drops the disabled field, so an update posted from the form has no job at all
        one_time_job = force_one_time_job()
        configuration, job = one_time_job.configuration, one_time_job.job
        self.login_with_policy(turbo_policy(self.group, "turbo.view_configuration"))
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("turbo:update_one_time_job", args=(configuration.pk, one_time_job.pk)),
                {"not_before": "2026-08-01 09:00:00",
                 "serial_numbers": "", "excluded_serial_numbers": ""},
                follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/configuration_detail.html")
        one_time_job.refresh_from_db()
        self.assertEqual(one_time_job.job, job)
        self.assertIsNotNone(one_time_job.not_before)

    # delete

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_one_time_job(self, post_event):
        one_time_job = force_one_time_job()
        configuration, pk = one_time_job.configuration, one_time_job.pk
        self.login_with_policy(turbo_policy(self.group, "turbo.view_configuration"))
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

    # PBAC: a forbid keyed on the job's kind refuses the schedule even though the role is granted
    # the action. The forbid rides on top of the broad grant turbo_policy() writes — one of two
    # shapes that work, the other being a kind-scoped permit on its own (pinned in test_pbac).

    def _forbid_kind(self, kind):
        Policy.objects.create(name="Turbo kind forbid", source=forbid_job_kind_policy(kind))

    def test_create_one_time_job_form_offers_only_the_allowed_kinds(self):
        # the picker narrows to what a policy would allow, so a kind-scoped grant does not lead an
        # operator into a 403 with the form lost
        configuration = force_configuration()
        allowed = force_command(backend=CommandBackend.SYSDIAGNOSE)
        refused = force_command(backend=CommandBackend.FILE_EXPORT)
        self.login_with_policy(turbo_policy(self.group, "turbo.view_configuration"))
        self._forbid_kind("file_export")
        response = self.client.get(reverse("turbo:create_one_time_job", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        offered = [value for value, _ in response.context["form"].fields["job"].choices if value]
        self.assertIn(allowed.job.pk, offered)
        self.assertNotIn(refused.job.pk, offered)
        # and the queryset is untouched, so a forged post still reaches the typed check
        self.assertIn(refused.job, response.context["form"].fields["job"].queryset)

    def test_create_one_time_job_refused_by_a_forbidden_kind(self):
        configuration = force_configuration()
        command = force_command(backend=CommandBackend.FILE_EXPORT)
        self.login_with_policy(turbo_policy(self.group, "turbo.view_configuration"))
        self._forbid_kind("file_export")
        response = self.client.post(
            reverse("turbo:create_one_time_job", args=(configuration.pk,)),
            {"job": str(command.job.pk), "serial_numbers": "", "excluded_serial_numbers": ""})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(OneTimeJob.objects.filter(job=command.job).count(), 0)

    def test_create_one_time_job_allowed_for_another_kind(self):
        configuration = force_configuration()
        command = force_command(backend=CommandBackend.SYSDIAGNOSE)
        self.login_with_policy(turbo_policy(self.group, "turbo.view_configuration"))
        self._forbid_kind("file_export")
        response = self.client.post(
            reverse("turbo:create_one_time_job", args=(configuration.pk,)),
            {"job": str(command.job.pk), "serial_numbers": "", "excluded_serial_numbers": ""},
            follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(OneTimeJob.objects.filter(job=command.job).count(), 1)

    def test_update_one_time_job_refused_by_a_forbidden_kind(self):
        command = force_command(backend=CommandBackend.FILE_EXPORT)
        one_time_job = force_one_time_job(job=command.job)
        self.login_with_policy(turbo_policy(self.group, "turbo.view_configuration"))
        self._forbid_kind("file_export")
        response = self.client.post(
            reverse("turbo:update_one_time_job", args=(one_time_job.configuration.pk, one_time_job.pk)),
            {"job": str(command.job.pk), "not_before": "2026-08-01 09:00:00",
             "serial_numbers": "", "excluded_serial_numbers": ""})
        self.assertEqual(response.status_code, 403)
        one_time_job.refresh_from_db()
        self.assertIsNone(one_time_job.not_before)

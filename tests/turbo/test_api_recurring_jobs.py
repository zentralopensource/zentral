from unittest.mock import patch
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import Policy
from zentral.contrib.inventory.models import Tag
from zentral.contrib.turbo.models import RecurringJob
from .utils import (VIEW_RECURRING_JOB_ACTION, TurboAPITestCase, forbid_job_kind_policy, force_command,
                    force_configuration, force_mscp_check, force_recurring_job, force_script,
                    recurring_job_update_data, turbo_policy, view_schedule_policy)


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
        # A command kind accepts the one-time mode only, because a repeated collection is not a
        # job. The console removes it from the choices. The API must give the error.
        configuration = force_configuration()
        command = force_command()
        self.set_policy(turbo_policy(self.group))
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
        self.set_policy(turbo_policy(self.group))
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
        self.set_policy(turbo_policy(self.group))
        response = self.post(reverse("turbo_api:recurring_jobs"),
                             {"configuration": str(configuration.pk), "job": str(script.job.pk),
                              "tags": [tag.pk], "serial_numbers": ["ABC123", "DEF456"]})
        self.assertEqual(response.status_code, 201)
        recurring_job = RecurringJob.objects.get(pk=response.json()["id"])
        self.assertEqual(list(recurring_job.tags.all()), [tag])
        self.assertEqual(recurring_job.serial_numbers, ["ABC123", "DEF456"])

    def test_create_recurring_job_duplicate(self):
        recurring_job = force_recurring_job()
        self.set_policy(turbo_policy(self.group))
        response = self.post(reverse("turbo_api:recurring_jobs"),
                             {"configuration": str(recurring_job.configuration.pk),
                              "job": str(recurring_job.job.pk)})
        self.assertEqual(response.status_code, 400)

    def test_create_recurring_job_disjoint_tags(self):
        configuration = force_configuration()
        script = force_script()
        tag = Tag.objects.create(name=get_random_string(12))
        self.set_policy(turbo_policy(self.group))
        response = self.post(reverse("turbo_api:recurring_jobs"),
                             {"configuration": str(configuration.pk), "job": str(script.job.pk),
                              "tags": [tag.pk], "excluded_tags": [tag.pk]})
        self.assertEqual(response.status_code, 400)

    def test_list_recurring_jobs_without_a_policy(self):
        # each recurring job has its own decision, so the list needs no permission, and it is empty
        force_recurring_job()
        self.set_permissions()
        response = self.get(reverse("turbo_api:recurring_jobs"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"count": 0, "next": None, "previous": None, "results": []})

    def test_get_recurring_job_without_a_policy(self):
        recurring_job = force_recurring_job()
        self.set_permissions()
        self.assertEqual(self.get(reverse("turbo_api:recurring_job", args=(recurring_job.pk,))).status_code, 403)

    def test_list_recurring_jobs(self):
        # creation order — LimitOffset pagination over an unordered queryset returns unstable pages
        recurring_jobs = [force_recurring_job() for _ in range(2)]
        self.set_policy(turbo_policy(self.group, actions=(VIEW_RECURRING_JOB_ACTION,)))
        response = self.get(reverse("turbo_api:recurring_jobs"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 2)
        self.assertEqual([j["id"] for j in response.json()["results"]],
                         [str(j.pk) for j in recurring_jobs])

    def test_list_recurring_jobs_constant_query_count(self):
        # the serializer renders tags/excluded_tags; the list queryset prefetches them → no per-row N+1
        self.set_policy(turbo_policy(self.group, actions=(VIEW_RECURRING_JOB_ACTION,)))
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
        self.set_policy(turbo_policy(self.group, actions=(VIEW_RECURRING_JOB_ACTION,)))
        response = self.get(reverse("turbo_api:recurring_jobs"),
                            {"configuration": str(recurring_job.configuration.pk)})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["results"][0]["id"], str(recurring_job.pk))

    def test_list_recurring_jobs_only_the_visible_ones(self):
        visible = force_recurring_job()
        force_recurring_job()
        self.set_policy(view_schedule_policy(
            self.group, f'resource in Turbo::Configuration::"{visible.configuration.pk}"'))
        response = self.get(reverse("turbo_api:recurring_jobs"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual([j["id"] for j in response.json()["results"]], [str(visible.pk)])

    def test_list_recurring_jobs_a_policy_that_sql_cannot_express(self):
        # like: one decision for each schedule, with the same rows
        visible = force_recurring_job()
        force_recurring_job()
        self.set_policy(view_schedule_policy(
            self.group, condition=(f'when {{ resource in Turbo::Configuration::"{visible.configuration.pk}" '
                                   '&& resource.job.kind like "*" }')))
        response = self.get(reverse("turbo_api:recurring_jobs"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual([j["id"] for j in response.json()["results"]], [str(visible.pk)])

    def test_get_recurring_job_not_visible(self):
        visible = force_recurring_job()
        hidden = force_recurring_job()
        self.set_policy(view_schedule_policy(
            self.group, f'resource in Turbo::Configuration::"{visible.configuration.pk}"'))
        self.assertEqual(self.get(reverse("turbo_api:recurring_job", args=(visible.pk,))).status_code, 200)
        self.assertEqual(self.get(reverse("turbo_api:recurring_job", args=(hidden.pk,))).status_code, 403)

    def test_get_recurring_job(self):
        recurring_job = force_recurring_job(interval=3600)
        self.set_policy(turbo_policy(self.group, actions=(VIEW_RECURRING_JOB_ACTION,)))
        response = self.get(reverse("turbo_api:recurring_job", args=(recurring_job.pk,)))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["id"], str(recurring_job.pk))
        self.assertEqual(data["interval"], 3600)

    def test_update_recurring_job(self):
        recurring_job = force_recurring_job(interval=3600)
        self.set_policy(turbo_policy(self.group))
        response = self.put(reverse("turbo_api:recurring_job", args=(recurring_job.pk,)),
                            recurring_job_update_data(recurring_job, interval=7200))
        self.assertEqual(response.status_code, 200)
        recurring_job.refresh_from_db()
        self.assertEqual(recurring_job.interval, 7200)

    def test_update_recurring_job_without_an_attribute(self):
        # The role cannot see the schedule. A field that the body leaves out would keep its stored
        # value, and the response would give it back.
        recurring_job = force_recurring_job(interval=3600, serial_numbers=["ABC123"])
        self.set_policy(turbo_policy(self.group))
        response = self.put(reverse("turbo_api:recurring_job", args=(recurring_job.pk,)),
                            {"configuration": str(recurring_job.configuration.pk),
                             "job": str(recurring_job.job.pk)})
        self.assertEqual(response.json(), {field: ["This field is required."]
                                           for field in ("interval", "tags", "excluded_tags",
                                                         "serial_numbers", "excluded_serial_numbers")})
        self.assertEqual(response.status_code, 400)

    def test_update_recurring_job_configuration_immutable(self):
        # re-pointing a schedule to another configuration would retarget that config's whole fleet
        recurring_job = force_recurring_job(interval=3600)
        other_configuration = force_configuration()
        self.set_policy(turbo_policy(self.group))
        response = self.put(reverse("turbo_api:recurring_job", args=(recurring_job.pk,)),
                            recurring_job_update_data(recurring_job, configuration=str(other_configuration.pk),
                                                      interval=7200))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"configuration": ["This field cannot be changed"]})
        recurring_job.refresh_from_db()
        self.assertEqual(recurring_job.interval, 3600)

    def test_update_recurring_job_job_immutable(self):
        # re-pointing a schedule to another job would strand its per-machine ledger rows
        recurring_job = force_recurring_job(interval=3600)
        other_script = force_script()
        self.set_policy(turbo_policy(self.group))
        response = self.put(reverse("turbo_api:recurring_job", args=(recurring_job.pk,)),
                            recurring_job_update_data(recurring_job, job=str(other_script.job.pk), interval=7200))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"job": ["This field cannot be changed"]})
        recurring_job.refresh_from_db()
        self.assertEqual(recurring_job.interval, 3600)

    def test_delete_recurring_job(self):
        recurring_job = force_recurring_job()
        pk = recurring_job.pk
        self.set_policy(turbo_policy(self.group))
        response = self.delete(reverse("turbo_api:recurring_job", args=(pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertFalse(RecurringJob.objects.filter(pk=pk).exists())

    # PBAC: the typed createRecurringJob, updateRecurringJob and deleteRecurringJob

    def _forbid_kind(self, kind):
        Policy.objects.update_or_create(name="Turbo API tests",
                                        defaults={"source": forbid_job_kind_policy(kind)})

    def test_create_recurring_job_refused_by_a_forbidden_kind(self):
        configuration = force_configuration()
        script = force_script()
        self.set_policy(turbo_policy(self.group))
        self._forbid_kind("script")
        response = self.post(reverse("turbo_api:recurring_jobs"),
                             {"configuration": str(configuration.pk), "job": str(script.job.pk)})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(RecurringJob.objects.filter(job=script.job).exists())

    def test_create_recurring_job_allowed_for_another_kind(self):
        configuration = force_configuration()
        mscp_check = force_mscp_check()
        self.set_policy(turbo_policy(self.group))
        self._forbid_kind("script")
        response = self.post(reverse("turbo_api:recurring_jobs"),
                             {"configuration": str(configuration.pk), "job": str(mscp_check.job.pk)})
        self.assertEqual(response.status_code, 201)

    def test_create_recurring_job_refused_in_another_configuration(self):
        allowed = force_configuration()
        other = force_configuration()
        script = force_script()
        self.set_policy("permit ("
                        f' principal in Role::"{self.group.pk}",'
                        ' action == Turbo::Action::"createRecurringJob",'
                        f' resource == Turbo::Configuration::"{allowed.pk}"'
                        ");\n")
        response = self.post(reverse("turbo_api:recurring_jobs"),
                             {"configuration": str(other.pk), "job": str(script.job.pk)})
        self.assertEqual(response.status_code, 403)
        response = self.post(reverse("turbo_api:recurring_jobs"),
                             {"configuration": str(allowed.pk), "job": str(script.job.pk)})
        self.assertEqual(response.status_code, 201)

    def test_update_recurring_job_refused_by_a_forbidden_kind(self):
        recurring_job = force_recurring_job(interval=3600)
        self.set_policy(turbo_policy(self.group))
        self._forbid_kind("script")
        response = self.put(reverse("turbo_api:recurring_job", args=(recurring_job.pk,)),
                            recurring_job_update_data(recurring_job, interval=7200))
        self.assertEqual(response.status_code, 403)
        recurring_job.refresh_from_db()
        self.assertEqual(recurring_job.interval, 3600)

    def test_delete_recurring_job_refused_by_a_forbidden_kind(self):
        recurring_job = force_recurring_job()
        self.set_policy(turbo_policy(self.group))
        self._forbid_kind("script")
        response = self.delete(reverse("turbo_api:recurring_job", args=(recurring_job.pk,)))
        self.assertEqual(response.status_code, 403)
        self.assertTrue(RecurringJob.objects.filter(pk=recurring_job.pk).exists())

from unittest.mock import patch
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from accounts.models import Policy
from zentral.contrib.turbo.command_backends import CommandBackend
from zentral.contrib.turbo.models import OneTimeJob
from .utils import (TurboAPITestCase, forbid_job_kind_policy, force_command,
                    force_configuration, force_one_time_job, force_script, turbo_policy)


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
        self.set_policy(turbo_policy(self.group))
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
        self.set_policy(turbo_policy(self.group))
        response = self.post(reverse("turbo_api:one_time_jobs"),
                             {"configuration": str(configuration.pk), "job": str(script.job.pk),
                              "not_before": "2026-07-02T10:00:00Z", "not_after": "2026-07-01T10:00:00Z"})
        self.assertEqual(response.status_code, 400)

    def test_create_one_time_job_disjoint_serial_numbers(self):
        configuration = force_configuration()
        script = force_script()
        self.set_policy(turbo_policy(self.group))
        response = self.post(reverse("turbo_api:one_time_jobs"),
                             {"configuration": str(configuration.pk), "job": str(script.job.pk),
                              "serial_numbers": ["ABC123"], "excluded_serial_numbers": ["ABC123"]})
        self.assertEqual(response.status_code, 400)

    def test_create_one_time_job_allows_duplicate(self):
        one_time_job = force_one_time_job()
        self.set_policy(turbo_policy(self.group))
        response = self.post(reverse("turbo_api:one_time_jobs"),
                             {"configuration": str(one_time_job.configuration.pk),
                              "job": str(one_time_job.job.pk)})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(
            OneTimeJob.objects.filter(configuration=one_time_job.configuration, job=one_time_job.job).count(),
            2,
        )

    def test_list_one_time_jobs(self):
        # creation order — LimitOffset pagination over an unordered queryset returns unstable pages
        one_time_jobs = [force_one_time_job() for _ in range(2)]
        self.set_permissions("turbo.view_onetimejob")
        response = self.get(reverse("turbo_api:one_time_jobs"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 2)
        self.assertEqual([j["id"] for j in response.json()["results"]],
                         [str(j.pk) for j in one_time_jobs])

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
        self.set_policy(turbo_policy(self.group))
        response = self.put(reverse("turbo_api:one_time_job", args=(one_time_job.pk,)),
                            {"configuration": str(one_time_job.configuration.pk),
                             "job": str(one_time_job.job.pk), "not_before": "2026-08-01T09:00:00Z"})
        self.assertEqual(response.status_code, 200)
        one_time_job.refresh_from_db()
        self.assertIsNotNone(one_time_job.not_before)

    def test_update_one_time_job_configuration_immutable(self):
        one_time_job = force_one_time_job()
        other_configuration = force_configuration()
        self.set_policy(turbo_policy(self.group))
        response = self.put(reverse("turbo_api:one_time_job", args=(one_time_job.pk,)),
                            {"configuration": str(other_configuration.pk),
                             "job": str(one_time_job.job.pk)})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"configuration": ["This field cannot be changed"]})

    def test_update_one_time_job_job_immutable(self):
        one_time_job = force_one_time_job()
        other_script = force_script()
        self.set_policy(turbo_policy(self.group))
        response = self.put(reverse("turbo_api:one_time_job", args=(one_time_job.pk,)),
                            {"configuration": str(one_time_job.configuration.pk),
                             "job": str(other_script.job.pk)})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"job": ["This field cannot be changed"]})

    def test_delete_one_time_job(self):
        one_time_job = force_one_time_job()
        pk = one_time_job.pk
        self.set_policy(turbo_policy(self.group))
        response = self.delete(reverse("turbo_api:one_time_job", args=(pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertFalse(OneTimeJob.objects.filter(pk=pk).exists())

    # PBAC: the typed createOneTimeJob / updateOneTimeJob / deleteOneTimeJob, which the retired
    # permissions could not express. This path had no typed check at all before.
    #
    # These tests refuse a kind with a FORBID on top of the broad grant login() writes, which is one
    # of two shapes that work. A kind-scoped permit works on its own too — no guard and no companion
    # forbid — and test_a_kind_scoped_permit_alone_is_enough pins that one.

    def _forbid_kind(self, kind):
        Policy.objects.update_or_create(name="Turbo API tests",
                                        defaults={"source": forbid_job_kind_policy(kind)})

    def test_create_one_time_job_refused_by_a_forbidden_kind(self):
        configuration = force_configuration()
        command = force_command(backend=CommandBackend.FILE_EXPORT)
        self.set_policy(turbo_policy(self.group))
        self._forbid_kind("file_export")
        response = self.post(reverse("turbo_api:one_time_jobs"),
                             {"configuration": str(configuration.pk), "job": str(command.job.pk)})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(OneTimeJob.objects.filter(job=command.job).count(), 0)

    def test_create_one_time_job_allowed_for_another_kind(self):
        # the same policy that refuses file_export leaves sysdiagnose alone
        configuration = force_configuration()
        command = force_command(backend=CommandBackend.SYSDIAGNOSE)
        self.set_policy(turbo_policy(self.group))
        self._forbid_kind("file_export")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.post(reverse("turbo_api:one_time_jobs"),
                                 {"configuration": str(configuration.pk), "job": str(command.job.pk)})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(OneTimeJob.objects.filter(job=command.job).count(), 1)

    def test_create_one_time_job_script_is_refusable_too(self):
        # every kind is policed, not only the command kinds: a script runs arbitrary code as root
        configuration = force_configuration()
        script = force_script()
        self.set_policy(turbo_policy(self.group))
        self._forbid_kind("script")
        response = self.post(reverse("turbo_api:one_time_jobs"),
                             {"configuration": str(configuration.pk), "job": str(script.job.pk)})
        self.assertEqual(response.status_code, 403)

    def test_update_one_time_job_refused_by_a_forbidden_kind(self):
        # the job of a schedule cannot change, but its window and tag scope can: widening the reach of
        # a file_export schedule is a scheduling act
        command = force_command(backend=CommandBackend.FILE_EXPORT)
        one_time_job = force_one_time_job(job=command.job)
        self.set_policy(turbo_policy(self.group))
        self._forbid_kind("file_export")
        response = self.put(reverse("turbo_api:one_time_job", args=(one_time_job.pk,)),
                            {"configuration": str(one_time_job.configuration.pk),
                             "job": str(command.job.pk), "not_after": "2027-01-01T09:00:00Z"})
        self.assertEqual(response.status_code, 403)
        one_time_job.refresh_from_db()
        self.assertIsNone(one_time_job.not_after)

    def test_update_one_time_job_allowed_for_another_kind(self):
        command = force_command(backend=CommandBackend.SYSDIAGNOSE)
        one_time_job = force_one_time_job(job=command.job)
        self.set_policy(turbo_policy(self.group))
        self._forbid_kind("file_export")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.put(reverse("turbo_api:one_time_job", args=(one_time_job.pk,)),
                                {"configuration": str(one_time_job.configuration.pk),
                                 "job": str(command.job.pk), "not_after": "2027-01-01T09:00:00Z"})
        self.assertEqual(response.status_code, 200)
        one_time_job.refresh_from_db()
        self.assertIsNotNone(one_time_job.not_after)

    def test_a_kind_scoped_permit_alone_is_enough(self):
        # the API counterpart of test_a_kind_scoped_permit_needs_no_guard_and_no_forbid, and the
        # headline claim of the change: this grant alone allows the kind it names and refuses the
        # others. No broad permit underneath it, no companion forbid, no has guard.
        configuration = force_configuration()
        allowed = force_command(backend=CommandBackend.SYSDIAGNOSE)
        refused = force_command(backend=CommandBackend.FILE_EXPORT)
        self.set_policy("permit ("
                        f' principal in Role::"{self.group.pk}",'
                        ' action == Turbo::Action::"createOneTimeJob",'
                        ' resource'
                        ') when { context.job.kind == "sysdiagnose" };\n')
        with self.captureOnCommitCallbacks(execute=True):
            response = self.post(reverse("turbo_api:one_time_jobs"),
                                 {"configuration": str(configuration.pk), "job": str(allowed.job.pk)})
        self.assertEqual(response.status_code, 201)
        response = self.post(reverse("turbo_api:one_time_jobs"),
                             {"configuration": str(configuration.pk), "job": str(refused.job.pk)})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(OneTimeJob.objects.filter(job=refused.job).count(), 0)

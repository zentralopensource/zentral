import uuid
from datetime import timedelta
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from django.core.files.base import ContentFile
from django.core.files.storage import storages
from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone

from zentral.conf import api_base_url
from zentral.contrib.inventory.models import MachineSnapshotCommit, MetaMachine
from zentral.contrib.turbo.command_backends import CommandBackend
from zentral.contrib.turbo.events import TurboArtifactDownloadedEvent
from zentral.contrib.turbo.models import (JobUpload, OneTimeJobMachine, RecurringJobMachine, UploadStatus,
                                          UploadVerification)
from zentral.contrib.turbo.pbac import ViewOneTimeJobMachineRequest
from zentral.core.events.base import EventMetadata
from zentral.utils.storage import StorageError

from .utils import (TurboAPITestCase, force_command, force_configuration, force_enrolled_machine,
                    force_one_time_job, force_recurring_job, force_script, turbo_policy)


SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
S3_STORAGE = {"default": {"BACKEND": "storages.backends.s3.S3Storage",
                          "OPTIONS": {"bucket_name": "zentral-tests",
                                      "access_key": "AKIAIOSFODNN7EXAMPLE",
                                      "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                                      "region_name": "us-east-1"}}}
ONE_TIME_ACTION = 'Turbo::Action::"viewOneTimeJobMachine"'
RECURRING_ACTION = 'Turbo::Action::"viewRecurringJobMachine"'
VIEW_ARTIFACT_ACTION = 'Turbo::Action::"viewJobUpload"'
DOWNLOAD_ARTIFACT_ACTION = 'Turbo::Action::"downloadJobUpload"'
ALL_ACTIONS = (ONE_TIME_ACTION, RECURRING_ACTION, VIEW_ARTIFACT_ACTION, DOWNLOAD_ARTIFACT_ACTION)
ONE_TIME_JOB_ACTION = 'Turbo::Action::"viewOneTimeJob"'
RECURRING_JOB_ACTION = 'Turbo::Action::"viewRecurringJob"'


class TurboJobMachineAPITestCase(TurboAPITestCase):

    # fixtures

    def _one_time_job(self, backend=CommandBackend.SYSDIAGNOSE):
        return force_one_time_job(configuration=force_configuration(), job=force_command(backend=backend).job)

    def _serial_number(self, configuration, in_mbu=False):
        enrollment, serial_number, _ = force_enrolled_machine(configuration=configuration,
                                                              meta_business_unit=self.mbu)
        if in_mbu:
            # the meta business units of the machine come from the inventory snapshots
            MachineSnapshotCommit.objects.commit_machine_snapshot_tree({
                "source": {"module": "zentral.contrib.turbo", "name": "Turbo"},
                "business_unit": enrollment.secret.get_api_enrollment_business_unit().serialize(),
                "serial_number": serial_number,
            })
        return serial_number

    def _otjm(self, one_time_job, in_mbu=False):
        serial_number = self._serial_number(one_time_job.configuration, in_mbu=in_mbu)
        now = timezone.now()
        return OneTimeJobMachine.objects.create(
            one_time_job=one_time_job, serial_number=serial_number,
            seen_version=1, last_result_version=1, last_seen_at=now - timedelta(minutes=5),
            first_result_at=now, last_result_at=now,
        )

    def _artifact(self, schedule, serial_number, artifact="archive", status=UploadStatus.UPLOADED):
        return JobUpload.objects.create(
            schedule_pk=schedule.pk, schedule_mode="one_time", serial_number=serial_number,
            run_id=uuid.uuid4(), artifact=artifact,
            key=f"turbo/uploads/{serial_number}/{schedule.pk}/x/{artifact}_{serial_number}.tar.gz",
            size=1024, sha256=SHA256, status=status, verification=UploadVerification.VERIFIED,
            completed_at=timezone.now(),
        )

    def _rjm(self, recurring_job):
        serial_number = self._serial_number(recurring_job.configuration)
        return RecurringJobMachine.objects.create(
            recurring_job=recurring_job, serial_number=serial_number,
            seen_version=1, seen_interval=3600, last_seen_at=timezone.now(),
        )

    def _allow(self, *actions, forbid=None, forbid_actions=None):
        policy = turbo_policy(self.group, actions=actions)
        if forbid:
            policy += f'forbid (principal, action in [{", ".join(forbid_actions or actions)}], resource {forbid});\n'
        self.set_policy(policy)

    # helpers

    def _one_time_list(self, one_time_job, **params):
        return self.get(reverse("turbo_api:one_time_job_machines", args=(one_time_job.pk,)), params)

    def _recurring_list(self, recurring_job, **params):
        return self.get(reverse("turbo_api:recurring_job_machines", args=(recurring_job.pk,)), params)

    @staticmethod
    def _serials(response):
        return [r["serial_number"] for r in response.json()["results"]]

    @staticmethod
    def _serialized_artifact(upload, download=True):
        return {
            "id": str(upload.pk),
            "run_id": str(upload.run_id),
            "artifact": upload.artifact,
            "mode": "put",
            "size": 1024,
            "sha256": SHA256,
            "truncated": False,
            "attempts": 0,
            "status": upload.status,
            "error_reason": None,
            "verification": "verified",
            "created_at": upload.created_at.isoformat(),
            "updated_at": upload.updated_at.isoformat(),
            "completed_at": upload.completed_at.isoformat(),
            "verified_at": None,
            "download_url": (f"{api_base_url()}{reverse('turbo_api:artifact_download', args=(upload.pk,))}"
                             if download else None),
        }

    # one-time job machines

    def test_one_time_unauthorized(self):
        one_time_job = self._one_time_job()
        response = self.get(reverse("turbo_api:one_time_job_machines", args=(one_time_job.pk,)),
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_one_time_unknown_job(self):
        self._allow(*ALL_ACTIONS)
        response = self.get(reverse("turbo_api:one_time_job_machines", args=(uuid.uuid4(),)))
        self.assertEqual(response.status_code, 404)

    def test_one_time_without_a_policy_is_empty(self):
        # a machine that the caller cannot see is not in the list, so a caller without a policy gets an
        # empty list, not a 403
        one_time_job = self._one_time_job()
        self._otjm(one_time_job)
        response = self._one_time_list(one_time_job)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"count": 0, "next": None, "previous": None, "results": []})

    def test_one_time_without_the_view_of_the_job(self):
        # one action decides each machine: the view of the job is another decision
        one_time_job = self._one_time_job(backend=CommandBackend.FILE_EXPORT)
        otjm = self._otjm(one_time_job)
        self._allow(*ALL_ACTIONS, forbid=f'in Turbo::OneTimeJob::"{one_time_job.pk}"',
                    forbid_actions=(ONE_TIME_JOB_ACTION,))
        self.assertEqual(self._serials(self._one_time_list(one_time_job)), [otjm.serial_number])

    def test_one_time(self):
        one_time_job = self._one_time_job(backend=CommandBackend.FILE_EXPORT)
        otjm = self._otjm(one_time_job)
        manifest = self._artifact(one_time_job, otjm.serial_number, artifact="manifest")
        archive = self._artifact(one_time_job, otjm.serial_number, status=UploadStatus.FAILED)
        self._artifact(self._one_time_job(), otjm.serial_number)  # another job
        self._otjm(self._one_time_job())  # another job
        self._allow(*ALL_ACTIONS)
        response = self._one_time_list(one_time_job)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            "count": 1, "next": None, "previous": None,
            "results": [{
                "serial_number": otjm.serial_number,
                "seen_version": 1,
                "last_result_version": 1,
                "first_seen_at": otjm.first_seen_at.isoformat(),
                "last_seen_at": otjm.last_seen_at.isoformat(),
                "first_result_at": otjm.first_result_at.isoformat(),
                "last_result_at": otjm.last_result_at.isoformat(),
                "removed_at": None,
                # no download for a failed upload
                "artifacts": [self._serialized_artifact(manifest),
                              self._serialized_artifact(archive, download=False)],
            }],
        })

    def test_one_time_filter_on_the_serial_number(self):
        one_time_job = self._one_time_job()
        otjm = self._otjm(one_time_job)
        self._otjm(one_time_job)
        self._allow(*ALL_ACTIONS)
        response = self._one_time_list(one_time_job, serial_number=otjm.serial_number)
        self.assertEqual(self._serials(response), [otjm.serial_number])

    def test_one_time_view_without_download(self):
        one_time_job = self._one_time_job()
        otjm = self._otjm(one_time_job)
        artifact = self._artifact(one_time_job, otjm.serial_number)
        self._allow(ONE_TIME_ACTION, VIEW_ARTIFACT_ACTION)
        results = self._one_time_list(one_time_job).json()["results"]
        self.assertEqual(results[0]["artifacts"], [self._serialized_artifact(artifact, download=False)])

    def test_one_time_artifacts_need_their_own_action(self):
        one_time_job = self._one_time_job()
        otjm = self._otjm(one_time_job)
        self._artifact(one_time_job, otjm.serial_number)
        self._allow(ONE_TIME_ACTION)
        results = self._one_time_list(one_time_job).json()["results"]
        self.assertEqual([r["artifacts"] for r in results], [[]])

    def test_one_time_a_configuration_forbid(self):
        # the one-time job is a member of its configuration, so the forbid reaches the rows
        one_time_job = self._one_time_job()
        self._otjm(one_time_job)
        self._allow(*ALL_ACTIONS, forbid=f'in Turbo::Configuration::"{one_time_job.configuration.pk}"')
        self.assertEqual(self._serials(self._one_time_list(one_time_job)), [])

    def test_one_time_a_one_time_job_forbid(self):
        one_time_job = self._one_time_job()
        self._otjm(one_time_job)
        self._allow(*ALL_ACTIONS, forbid=f'in Turbo::OneTimeJob::"{one_time_job.pk}"')
        self.assertEqual(self._serials(self._one_time_list(one_time_job)), [])

    def test_one_time_a_meta_business_unit_forbid(self):
        one_time_job = self._one_time_job()
        self._otjm(one_time_job, in_mbu=True)
        otjm = self._otjm(one_time_job)
        self._allow(*ALL_ACTIONS, forbid=f'in Inventory::MetaBusinessUnit::"{self.mbu.pk}"')
        self.assertEqual(self._serials(self._one_time_list(one_time_job)), [otjm.serial_number])

    def test_one_time_a_policy_can_read_the_job_kind(self):
        one_time_job = self._one_time_job(backend=CommandBackend.FILE_EXPORT)
        self._otjm(one_time_job)
        self.set_policy(turbo_policy(self.group, actions=ALL_ACTIONS)
                        + f"forbid (principal, action == {ONE_TIME_ACTION}, resource) "
                          'when { resource.job.kind == "file_export" };\n')
        self.assertEqual(self._serials(self._one_time_list(one_time_job)), [])

    def test_one_time_an_artifact_forbid_keeps_the_machine(self):
        one_time_job = self._one_time_job()
        otjm = self._otjm(one_time_job)
        self._artifact(one_time_job, otjm.serial_number)
        self._allow(*ALL_ACTIONS, forbid=f'in Turbo::OneTimeJob::"{one_time_job.pk}"',
                    forbid_actions=(VIEW_ARTIFACT_ACTION,))
        results = self._one_time_list(one_time_job).json()["results"]
        self.assertEqual([(r["serial_number"], r["artifacts"]) for r in results], [(otjm.serial_number, [])])

    def test_one_time_the_page_comes_after_the_decisions(self):
        # the first machine is forbidden: a page cut before the decisions is empty
        one_time_job = self._one_time_job()
        for _ in range(3):
            self._otjm(one_time_job)
        self._allow(*ALL_ACTIONS)
        serial_numbers = self._serials(self._one_time_list(one_time_job))
        machine = MetaMachine(serial_numbers[0])
        self._allow(*ALL_ACTIONS, forbid=f'in Inventory::Machine::"{machine.get_urlsafe_serial_number()}"')
        response_json = self._one_time_list(one_time_job, limit=1).json()
        self.assertEqual(response_json["count"], 2)
        self.assertEqual([r["serial_number"] for r in response_json["results"]], [serial_numbers[1]])

    def test_one_time_artifacts_of_the_page_only(self):
        one_time_job = self._one_time_job()
        for _ in range(2):
            self._artifact(one_time_job, self._otjm(one_time_job).serial_number)
        self._allow(*ALL_ACTIONS)
        serial_numbers = self._serials(self._one_time_list(one_time_job))
        with CaptureQueriesContext(connection) as queries:
            results = self._one_time_list(one_time_job, limit=1).json()["results"]
        self.assertEqual([len(r["artifacts"]) for r in results], [1])
        upload_queries = [q["sql"] for q in queries.captured_queries if 'FROM "turbo_jobupload"' in q["sql"]]
        self.assertEqual(len(upload_queries), 1)
        self.assertIn(serial_numbers[0], upload_queries[0])
        self.assertNotIn(serial_numbers[1], upload_queries[0])

    def test_one_time_queries_do_not_grow_with_the_machines(self):
        # one query for the meta business units of all the machines
        self._allow(*ALL_ACTIONS)
        counts = []
        for machine_count in (2, 5):
            one_time_job = self._one_time_job()
            for _ in range(machine_count):
                otjm = self._otjm(one_time_job, in_mbu=True)
                self._artifact(one_time_job, otjm.serial_number)
            with CaptureQueriesContext(connection) as queries:
                response = self._one_time_list(one_time_job)
            self.assertEqual(response.json()["count"], machine_count)
            counts.append(len(queries.captured_queries))
        self.assertEqual(counts[0], counts[1])

    def _forbid_outside_the_meta_business_unit(self):
        self.set_policy(turbo_policy(self.group, actions=ALL_ACTIONS)
                        + f"forbid (principal, action == {ONE_TIME_ACTION}, resource) "
                          f'unless {{ resource in Inventory::MetaBusinessUnit::"{self.mbu.pk}" }};\n')

    @patch.object(ViewOneTimeJobMachineRequest, "requests_for_rows")
    def test_one_time_the_policies_are_one_sql_filter(self, requests_for_rows):
        one_time_job = self._one_time_job()
        for in_mbu in (True, False, True):
            self._otjm(one_time_job, in_mbu=in_mbu)
        self._forbid_outside_the_meta_business_unit()
        with CaptureQueriesContext(connection) as queries:
            response_json = self._one_time_list(one_time_job, limit=1).json()
        requests_for_rows.assert_not_called()
        self.assertEqual(response_json["count"], 2)
        self.assertEqual(len(response_json["results"]), 1)
        # the count and the page, in SQL
        row_queries = [q["sql"] for q in queries.captured_queries if 'FROM "turbo_onetimejobmachine"' in q["sql"]]
        self.assertEqual(len(row_queries), 2)
        self.assertIn("COUNT(", row_queries[0])
        self.assertIn("LIMIT 1", row_queries[1])

    def test_one_time_a_policy_that_sql_cannot_express(self):
        # like: one decision for each machine, with the same rows
        sysdiagnose_job = self._one_time_job()
        otjm = self._otjm(sysdiagnose_job)
        file_export_job = self._one_time_job(backend=CommandBackend.FILE_EXPORT)
        self._otjm(file_export_job)
        self.set_policy(turbo_policy(self.group, actions=ALL_ACTIONS)
                        + f"forbid (principal, action == {ONE_TIME_ACTION}, resource) "
                          'when { resource.job.kind like "file*" };\n')
        with patch.object(ViewOneTimeJobMachineRequest, "requests_for_rows",
                          wraps=ViewOneTimeJobMachineRequest.requests_for_rows) as requests_for_rows:
            self.assertEqual(self._serials(self._one_time_list(sysdiagnose_job)), [otjm.serial_number])
            self.assertEqual(self._serials(self._one_time_list(file_export_job)), [])
        self.assertEqual(requests_for_rows.call_count, 2)

    def test_one_time_queries_do_not_grow_with_the_machines_with_a_filter(self):
        self._forbid_outside_the_meta_business_unit()
        counts = []
        for machine_count in (2, 5):
            one_time_job = self._one_time_job()
            for _ in range(machine_count):
                otjm = self._otjm(one_time_job, in_mbu=True)
                self._artifact(one_time_job, otjm.serial_number)
            self._otjm(one_time_job)  # outside the meta business unit
            with CaptureQueriesContext(connection) as queries:
                response = self._one_time_list(one_time_job)
            self.assertEqual(response.json()["count"], machine_count)
            counts.append(len(queries.captured_queries))
        self.assertEqual(counts[0], counts[1])

    # recurring job machines

    def test_recurring_unknown_job(self):
        self._allow(*ALL_ACTIONS)
        response = self.get(reverse("turbo_api:recurring_job_machines", args=(uuid.uuid4(),)))
        self.assertEqual(response.status_code, 404)

    def test_recurring(self):
        recurring_job = force_recurring_job(configuration=force_configuration(), job=force_script().job)
        rjm = self._rjm(recurring_job)
        self._allow(*ALL_ACTIONS)
        response = self._recurring_list(recurring_job)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            "count": 1, "next": None, "previous": None,
            "results": [{
                "serial_number": rjm.serial_number,
                "seen_version": 1,
                "seen_interval": 3600,
                "last_result_version": None,
                "first_seen_at": rjm.first_seen_at.isoformat(),
                "last_seen_at": rjm.last_seen_at.isoformat(),
                "first_result_at": None,
                "last_result_at": None,
                "removed_at": None,
            }],
        })

    def test_recurring_without_the_view_of_the_job(self):
        # one action decides each machine: the view of the job is another decision
        recurring_job = force_recurring_job(configuration=force_configuration(), job=force_script().job)
        rjm = self._rjm(recurring_job)
        self._allow(*ALL_ACTIONS, forbid=f'in Turbo::RecurringJob::"{recurring_job.pk}"',
                    forbid_actions=(RECURRING_JOB_ACTION,))
        self.assertEqual(self._serials(self._recurring_list(recurring_job)), [rjm.serial_number])

    def test_recurring_a_configuration_forbid(self):
        recurring_job = force_recurring_job(configuration=force_configuration(), job=force_script().job)
        self._rjm(recurring_job)
        self._allow(*ALL_ACTIONS, forbid=f'in Turbo::Configuration::"{recurring_job.configuration.pk}"')
        self.assertEqual(self._serials(self._recurring_list(recurring_job)), [])

    def test_recurring_needs_its_own_action(self):
        recurring_job = force_recurring_job(configuration=force_configuration(), job=force_script().job)
        self._rjm(recurring_job)
        self._allow(ONE_TIME_ACTION)
        self.assertEqual(self._serials(self._recurring_list(recurring_job)), [])

    # artifact download

    def _download(self, upload, include_token=True):
        return self.get(reverse("turbo_api:artifact_download", args=(upload.pk,)), include_token=include_token)

    def test_download_unauthorized(self):
        one_time_job = self._one_time_job()
        upload = self._artifact(one_time_job, self._otjm(one_time_job).serial_number)
        self.assertEqual(self._download(upload, include_token=False).status_code, 401)

    def test_download_needs_the_download_action(self):
        # the Viewer group has viewJobUpload, but not downloadJobUpload
        one_time_job = self._one_time_job()
        upload = self._artifact(one_time_job, self._otjm(one_time_job).serial_number)
        self._allow(ONE_TIME_ACTION, VIEW_ARTIFACT_ACTION)
        self.assertEqual(self._download(upload).status_code, 403)

    def test_download_a_one_time_job_forbid(self):
        one_time_job = self._one_time_job()
        upload = self._artifact(one_time_job, self._otjm(one_time_job).serial_number)
        self._allow(*ALL_ACTIONS, forbid=f'in Turbo::OneTimeJob::"{one_time_job.pk}"')
        self.assertEqual(self._download(upload).status_code, 403)

    @override_settings(STORAGES=S3_STORAGE)
    @patch("zentral.contrib.turbo.uploads.stat_object", return_value={"size": 1024, "digests": {}})
    def test_download_redirects_with_the_disposition(self, stat_object):
        one_time_job = self._one_time_job()
        upload = self._artifact(one_time_job, self._otjm(one_time_job).serial_number, artifact="manifest")
        self._allow(DOWNLOAD_ARTIFACT_ACTION)
        response = self._download(upload)
        self.assertEqual(response.status_code, 302)
        query = parse_qs(urlparse(response["Location"]).query)
        self.assertIn("attachment", query["response-content-disposition"][0])

    def test_download_serves_the_file(self):
        one_time_job = self._one_time_job()
        upload = self._artifact(one_time_job, self._otjm(one_time_job).serial_number)
        storage = storages["default"]
        storage.save(upload.key, ContentFile(b"a sysdiagnose"))
        self.addCleanup(storage.delete, upload.key)
        self._allow(DOWNLOAD_ARTIFACT_ACTION)
        response = self._download(upload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(b"".join(response.streaming_content), b"a sysdiagnose")
        self.assertIn("attachment", response["Content-Disposition"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_download_posts_an_event(self, post_event):
        one_time_job = self._one_time_job()
        upload = self._artifact(one_time_job, self._otjm(one_time_job).serial_number)
        storage = storages["default"]
        storage.save(upload.key, ContentFile(b"a sysdiagnose"))
        self.addCleanup(storage.delete, upload.key)
        self._allow(DOWNLOAD_ARTIFACT_ACTION)
        self.assertEqual(self._download(upload).status_code, 200)
        events = [c.args[0] for c in post_event.call_args_list
                  if isinstance(c.args[0], TurboArtifactDownloadedEvent)]
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.metadata.machine_serial_number, upload.serial_number)
        self.assertEqual(event.metadata.request.user.username, self.service_account.username)
        self.assertEqual(event.payload, {
            "schedule": {"mode": "one_time", "pk": str(one_time_job.pk)},
            "artifact": "archive",
            "upload": {"pk": str(upload.pk), "size": 1024, "sha256": SHA256},
        })

    @patch("zentral.contrib.turbo.uploads.stat_object", side_effect=StorageError("403"))
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_download_when_the_storage_does_not_give_the_file(self, post_event, stat_object):
        # for example S3 without s3:ListBucket, which answers a 403 for a missing key
        one_time_job = self._one_time_job()
        upload = self._artifact(one_time_job, self._otjm(one_time_job).serial_number)
        self._allow(DOWNLOAD_ARTIFACT_ACTION)
        with self.assertLogs("zentral.contrib.turbo.uploads", level="ERROR"):
            response = self._download(upload)
        self.assertEqual(response.status_code, 503)
        self.assertFalse(any(isinstance(c.args[0], TurboArtifactDownloadedEvent) for c in post_event.call_args_list))

    def test_the_download_event_links_the_schedule(self):
        for mode, key in (("one_time", "turbo_one_time_job"), ("recurring", "turbo_recurring_job")):
            event = TurboArtifactDownloadedEvent(EventMetadata(), {"schedule": {"mode": mode, "pk": "a"}})
            self.assertEqual(event.get_linked_objects_keys(), {key: [("a",)]})

    def test_download_of_an_upload_that_failed(self):
        one_time_job = self._one_time_job()
        upload = self._artifact(one_time_job, self._otjm(one_time_job).serial_number, status=UploadStatus.FAILED)
        self._allow(DOWNLOAD_ARTIFACT_ACTION)
        self.assertEqual(self._download(upload).status_code, 404)

    def test_download_of_a_deleted_object(self):
        # expected: the bucket rule deletes objects, and the rows stay
        one_time_job = self._one_time_job()
        upload = self._artifact(one_time_job, self._otjm(one_time_job).serial_number)
        self._allow(DOWNLOAD_ARTIFACT_ACTION)
        self.assertEqual(self._download(upload).status_code, 404)

    def test_download_of_an_upload_without_its_schedule(self):
        # no schedule: no configuration and no job for the decision
        one_time_job = self._one_time_job()
        upload = self._artifact(one_time_job, self._otjm(one_time_job).serial_number)
        one_time_job.delete()
        self._allow(DOWNLOAD_ARTIFACT_ACTION)
        self.assertEqual(self._download(upload).status_code, 404)

    def test_download_of_an_unknown_upload(self):
        self._allow(DOWNLOAD_ARTIFACT_ACTION)
        response = self.get(reverse("turbo_api:artifact_download", args=(uuid.uuid4(),)))
        self.assertEqual(response.status_code, 404)

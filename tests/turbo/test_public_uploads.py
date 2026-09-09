import hashlib
import json
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.core.files.storage import storages
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from zentral.contrib.turbo.command_backends import CommandBackend
from zentral.contrib.turbo.events import TurboRequestEvent
from zentral.contrib.turbo.models import Job, JobUpload, OneTimeJobMachine, UploadStatus
from zentral.contrib.turbo.uploads import (MAX_PENDING_UPLOADS, MAX_UPLOAD_ATTEMPTS,
                                           sign_hosted_upload)

from .utils import (TurboPublicTestCase, force_command, force_configuration, force_enrolled_machine,
                    force_one_time_job, force_recurring_job, force_script)


SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
BODY = b"turbo" * 200
S3_STORAGE = {"default": {"BACKEND": "storages.backends.s3.S3Storage",
                          "OPTIONS": {"bucket_name": "zentral-tests",
                                      "access_key": "AKIAIOSFODNN7EXAMPLE",
                                      "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                                      "region_name": "us-east-1"}}}


class TurboUploadMintTestCase(TurboPublicTestCase):
    def _mint(self, token, body):
        return self.client.post(
            reverse("turbo_public:uploads"),
            data=json.dumps(body),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}",
        )

    def _enrolled(self, configuration=None):
        configuration = configuration or force_configuration()
        enrollment, serial_number, token = force_enrolled_machine(
            configuration=configuration, meta_business_unit=self.mbu)
        return configuration, serial_number, token

    def _scheduled_command(self, backend=CommandBackend.SYSDIAGNOSE, configuration=None,
                           serial_number=None):
        configuration = configuration or force_configuration()
        command = force_command(backend=backend)
        one_time_job = force_one_time_job(configuration=configuration, job=command.job,
                                          serial_numbers=[serial_number] if serial_number else None)
        return configuration, one_time_job

    def _body(self, one_time_job, artifact="archive", size=1024, run_id=None):
        return {"schedule_pk": str(one_time_job.pk), "run_id": str(run_id or uuid.uuid4()),
                "artifact": artifact, "size": size, "sha256": SHA256,
                "digests": {"crc64nvme": "nD+hB17SSLE="}}

    # authentication

    def test_unauthenticated(self):
        response = self.client.post(reverse("turbo_public:uploads"), data="{}",
                                    content_type="application/json")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"error": "unauthenticated"})

    # the happy path

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_mint(self, post_event):
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(configuration=configuration,
                                                  serial_number=serial_number)
        response = self._mint(token, self._body(one_time_job))
        self.assertEqual(response.status_code, 200)
        answer = response.json()
        self.assertEqual(answer["mode"], "put")
        self.assertTrue(answer["url"])
        self.assertEqual(answer["headers"]["Content-Length"], "1024")
        self.assertEqual(answer["headers"]["Content-Type"], "application/gzip")
        upload = JobUpload.objects.get(schedule_pk=one_time_job.pk, serial_number=serial_number)
        self.assertEqual(answer["key"], upload.key)
        self.assertEqual(upload.status, UploadStatus.PENDING)
        self.assertEqual(upload.attempts, 1)
        events = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], TurboRequestEvent)]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].payload["request_type"], "upload")
        self.assertEqual(events[0].payload["artifact"], "archive")

    def test_key_is_the_server_s_and_holds_the_artifact_filename(self):
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(configuration=configuration,
                                                  serial_number=serial_number)
        key = self._mint(token, self._body(one_time_job)).json()["key"]
        upload = JobUpload.objects.get(schedule_pk=one_time_job.pk)
        self.assertTrue(key.startswith(f"turbo/uploads/{serial_number}/{one_time_job.pk}/{upload.pk}/"))
        # the declaration owns the stem and the extension, so a browser saves the right name unaided
        self.assertTrue(key.endswith(".tar.gz"))
        self.assertIn(f"sysdiagnose_{serial_number}_", key)
        # and the agent's run id is never in a path
        self.assertNotIn(str(upload.run_id), key)

    def test_a_retry_re_signs_the_same_key(self):
        # the whole point of a stateful mint: a retry overwrites in place instead of leaving a
        # half-written twin at a fresh key
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(configuration=configuration,
                                                  serial_number=serial_number)
        run_id = uuid.uuid4()
        first = self._mint(token, self._body(one_time_job, run_id=run_id)).json()
        second = self._mint(token, self._body(one_time_job, run_id=run_id)).json()
        self.assertEqual(first["key"], second["key"])
        self.assertEqual(JobUpload.objects.filter(schedule_pk=one_time_job.pk).count(), 1)
        self.assertEqual(JobUpload.objects.get(schedule_pk=one_time_job.pk).attempts, 2)

    def test_two_runs_of_one_schedule_get_two_rows(self):
        # what run_id buys, and the reason the plane can serve a recurring schedule at all
        configuration, serial_number, token = self._enrolled()
        command = force_command(backend=CommandBackend.SYSDIAGNOSE)
        recurring_job = force_recurring_job(configuration=configuration, job=command.job)
        for _ in range(2):
            body = {"schedule_pk": str(recurring_job.pk), "run_id": str(uuid.uuid4()),
                    "artifact": "archive", "size": 1024, "sha256": SHA256}
            self.assertEqual(self._mint(token, body).status_code, 200)
        rows = JobUpload.objects.filter(schedule_pk=recurring_job.pk)
        self.assertEqual(rows.count(), 2)
        self.assertEqual(len({row.key for row in rows}), 2)

    def test_two_artifacts_of_one_run_get_two_rows(self):
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(backend=CommandBackend.FILE_EXPORT,
                                                  configuration=configuration,
                                                  serial_number=serial_number)
        run_id = uuid.uuid4()
        for artifact in ("manifest", "archive"):
            response = self._mint(token, self._body(one_time_job, artifact=artifact, run_id=run_id))
            self.assertEqual(response.status_code, 200)
        self.assertEqual(JobUpload.objects.filter(run_id=run_id).count(), 2)
        keys = {row.artifact: row.key for row in JobUpload.objects.filter(run_id=run_id)}
        self.assertTrue(keys["manifest"].endswith(".json"))
        self.assertTrue(keys["archive"].endswith(".zip"))

    # malformed requests — terminal for the agent, so a 400

    def test_missing_run_id(self):
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(configuration=configuration,
                                                  serial_number=serial_number)
        body = self._body(one_time_job)
        del body["run_id"]
        response = self._mint(token, body)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "missing_run_id"})

    def test_invalid_run_id(self):
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(configuration=configuration,
                                                  serial_number=serial_number)
        response = self._mint(token, {**self._body(one_time_job), "run_id": "not-a-uuid"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "invalid_run_id"})

    def test_missing_artifact(self):
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(configuration=configuration,
                                                  serial_number=serial_number)
        body = self._body(one_time_job)
        del body["artifact"]
        response = self._mint(token, body)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "missing_artifact"})

    def test_invalid_size(self):
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(configuration=configuration,
                                                  serial_number=serial_number)
        response = self._mint(token, {**self._body(one_time_job), "size": 0})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "invalid_size"})

    def test_invalid_sha256(self):
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(configuration=configuration,
                                                  serial_number=serial_number)
        response = self._mint(token, {**self._body(one_time_job), "sha256": "tooshort"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "invalid_sha256"})

    def test_sha256_of_the_right_length_but_not_hex(self):
        # a length check is not a format check. 64 characters of anything used to reach the encoder,
        # which cannot unhexlify them — a 500 on a device endpoint, where the agent needed a 400.
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(configuration=configuration,
                                                  serial_number=serial_number)
        body = self._body(one_time_job)
        body["sha256"] = "z" * 64
        response = self._mint(token, body)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "invalid_sha256"})
        self.assertEqual(JobUpload.objects.count(), 0)

    def test_sha256_is_stored_lowercase(self):
        # an agent formatting with %X is not wrong, and verification has one form to compare against
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(configuration=configuration,
                                                  serial_number=serial_number)
        run_id = uuid.uuid4()
        body = self._body(one_time_job, run_id=run_id)
        body["sha256"] = SHA256.upper()
        self.assertEqual(self._mint(token, body).status_code, 200)
        self.assertEqual(JobUpload.objects.get(run_id=run_id).sha256, SHA256)

    def test_a_digest_too_long_for_its_column(self):
        # the columns hold 32 characters, and Postgres answers a longer value with a DataError —
        # another 500 the agent cannot act on
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(configuration=configuration,
                                                  serial_number=serial_number)
        body = self._body(one_time_job)
        body["digests"] = {"crc64nvme": "A" * 64}
        response = self._mint(token, body)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "invalid_digests"})
        self.assertEqual(JobUpload.objects.count(), 0)

    def test_digests_is_not_an_object(self):
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(configuration=configuration,
                                                  serial_number=serial_number)
        body = self._body(one_time_job)
        body["digests"] = "nD+hB17SSLE="
        response = self._mint(token, body)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "invalid_digests"})

    def test_an_unknown_digest_algorithm_is_dropped_not_refused(self):
        # the set the server asks for can grow, and an agent that computed one this release does not
        # store has done nothing wrong
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(configuration=configuration,
                                                  serial_number=serial_number)
        run_id = uuid.uuid4()
        body = self._body(one_time_job, run_id=run_id)
        body["digests"] = {"crc64nvme": "nD+hB17SSLE=", "blake3": "whatever"}
        self.assertEqual(self._mint(token, body).status_code, 200)
        upload = JobUpload.objects.get(run_id=run_id)
        self.assertEqual(upload.crc64nvme, "nD+hB17SSLE=")

    def test_unknown_artifact(self):
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(configuration=configuration,
                                                  serial_number=serial_number)
        response = self._mint(token, self._body(one_time_job, artifact="yolo"))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "unknown_artifact"})

    def test_a_kind_that_declares_no_artifact(self):
        # a script produces a verdict, not a file: nothing to mint for, and no retry will change it
        configuration, serial_number, token = self._enrolled()
        one_time_job = force_one_time_job(configuration=configuration, job=force_script().job,
                                          serial_numbers=[serial_number])
        response = self._mint(token, self._body(one_time_job))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "unknown_artifact"})

    def test_attempts_exhausted(self):
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(configuration=configuration,
                                                  serial_number=serial_number)
        run_id = uuid.uuid4()
        for _ in range(MAX_UPLOAD_ATTEMPTS):
            self.assertEqual(self._mint(token, self._body(one_time_job, run_id=run_id)).status_code, 200)
        response = self._mint(token, self._body(one_time_job, run_id=run_id))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "attempts_exhausted"})
        # a refusal costs the agent nothing: the count did not move
        self.assertEqual(JobUpload.objects.get(run_id=run_id).attempts, MAX_UPLOAD_ATTEMPTS)

    def test_too_large(self):
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(backend=CommandBackend.FILE_EXPORT,
                                                  configuration=configuration,
                                                  serial_number=serial_number)
        response = self._mint(token, self._body(one_time_job, size=10 * 2**30))
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json(), {"error": "too_large"})
        self.assertEqual(JobUpload.objects.count(), 0)

    # requests the agent should abandon silently

    @override_settings(STORAGES=S3_STORAGE)
    def test_the_kind_cap_applies_under_the_deployment_ceiling(self):
        # file_export caps at 500 MiB, well under the 2 GiB an S3 deployment would take. Read off the
        # model with getattr() the cap was always None and only the deployment ceiling applied, so a
        # 600 MiB export minted fine — the old test used 10 GiB and could not see it.
        configuration, serial_number, token = self._enrolled()
        command = force_command(backend=CommandBackend.FILE_EXPORT)
        one_time_job = force_one_time_job(configuration=configuration, job=command.job,
                                          serial_numbers=[serial_number])
        response = self._mint(token, self._body(one_time_job, size=600 * 2**20))
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json(), {"error": "too_large"})
        # and just under it is fine, so the ceiling is the kind's and not something smaller
        response = self._mint(token, self._body(one_time_job, size=499 * 2**20))
        self.assertEqual(response.status_code, 200)

    @override_settings(STORAGES=S3_STORAGE)
    def test_the_deployment_ceiling_still_clamps_a_larger_kind(self):
        # sysdiagnose declares 2 GiB, which the hosted ceiling is far below: the lower of the two wins
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(configuration=configuration,
                                                  serial_number=serial_number)
        with override_settings(STORAGES={"default": {"BACKEND": "django.core.files.storage."
                                                                "InMemoryStorage"}}):
            response = self._mint(token, self._body(one_time_job, size=64 * 2**20))
        self.assertEqual(response.status_code, 413)

    def test_pending_rows_are_bounded_per_schedule(self):
        # run_id is the agent's, and a gate only closes on a result: without a bound a machine that
        # never reports could mint a fresh row, and a fresh write credential, for every id it made up
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(configuration=configuration,
                                                  serial_number=serial_number)
        for _ in range(MAX_PENDING_UPLOADS):
            self.assertEqual(self._mint(token, self._body(one_time_job)).status_code, 200)
        response = self._mint(token, self._body(one_time_job))
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.json(), {"error": "too_many_pending"})
        self.assertEqual(JobUpload.objects.filter(schedule_pk=one_time_job.pk).count(),
                         MAX_PENDING_UPLOADS)

    def test_a_retry_of_a_bounded_schedule_is_not_refused(self):
        # the bound counts rows, and a retry reuses one: an agent at the limit can still finish the
        # runs it already has
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(configuration=configuration,
                                                  serial_number=serial_number)
        runs = [uuid.uuid4() for _ in range(MAX_PENDING_UPLOADS)]
        for run_id in runs:
            self._mint(token, self._body(one_time_job, run_id=run_id))
        self.assertEqual(self._mint(token, self._body(one_time_job)).status_code, 429)
        self.assertEqual(self._mint(token, self._body(one_time_job, run_id=runs[0])).status_code, 200)

    def test_a_retry_moves_the_storage_digests_with_the_bytes(self):
        # left on the first mint's values they would describe bytes that are no longer at the key,
        # and the verification axis would compare against the wrong digest
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(configuration=configuration,
                                                  serial_number=serial_number)
        run_id = uuid.uuid4()
        self._mint(token, self._body(one_time_job, run_id=run_id))
        second = self._body(one_time_job, run_id=run_id, size=2048)
        second["sha256"] = "a" * 64
        second["digests"] = {"crc64nvme": "AAAAAAAAAAA="}
        self._mint(token, second)
        upload = JobUpload.objects.get(run_id=run_id)
        self.assertEqual(upload.size, 2048)
        self.assertEqual(upload.sha256, "a" * 64)
        self.assertEqual(upload.crc64nvme, "AAAAAAAAAAA=")

    def test_unknown_schedule(self):
        configuration, serial_number, token = self._enrolled()
        response = self._mint(token, {"schedule_pk": str(uuid.uuid4()), "run_id": str(uuid.uuid4()),
                                      "artifact": "archive", "size": 1024, "sha256": SHA256})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {"error": "unknown_schedule"})

    def test_another_configuration_s_schedule(self):
        # the schedule exists, but not for this machine: without the configuration filter a machine
        # could mint against any schedule whose pk it learned
        configuration, serial_number, token = self._enrolled()
        _, other = self._scheduled_command()
        response = self._mint(token, self._body(other))
        self.assertEqual(response.status_code, 404)

    def test_out_of_scope_schedule(self):
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(configuration=configuration,
                                                  serial_number="SOMEONEELSE")
        response = self._mint(token, self._body(one_time_job))
        self.assertEqual(response.status_code, 404)

    def test_schedule_outside_its_window(self):
        configuration, serial_number, token = self._enrolled()
        command = force_command(backend=CommandBackend.SYSDIAGNOSE)
        one_time_job = force_one_time_job(configuration=configuration, job=command.job,
                                          serial_numbers=[serial_number],
                                          not_after=timezone.now() - timedelta(hours=1))
        response = self._mint(token, self._body(one_time_job))
        self.assertEqual(response.status_code, 404)

    def test_gate_already_closed(self):
        # a result came back while the agent was still uploading: the shot is spent, and an object
        # written now could never be referenced by anything
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(configuration=configuration,
                                                  serial_number=serial_number)
        OneTimeJobMachine.objects.create(one_time_job=one_time_job, serial_number=serial_number,
                                         last_result_at=timezone.now())
        response = self._mint(token, self._body(one_time_job))
        self.assertEqual(response.status_code, 410)
        self.assertEqual(response.json(), {"error": "gate_closed"})

    def test_already_uploaded(self):
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(configuration=configuration,
                                                  serial_number=serial_number)
        run_id = uuid.uuid4()
        self._mint(token, self._body(one_time_job, run_id=run_id))
        JobUpload.objects.filter(run_id=run_id).update(status=UploadStatus.UPLOADED)
        response = self._mint(token, self._body(one_time_job, run_id=run_id))
        self.assertEqual(response.status_code, 410)
        self.assertEqual(response.json(), {"error": "already_uploaded"})

    # the mint writes exactly one row, its own

    def test_the_mint_creates_no_tracker_row(self):
        # a run that mints and never reports must leave no trace in a ledger the plane does not own —
        # otherwise the gate machinery would see a machine it never heard from
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(configuration=configuration,
                                                  serial_number=serial_number)
        self.assertEqual(self._mint(token, self._body(one_time_job)).status_code, 200)
        self.assertEqual(OneTimeJobMachine.objects.filter(one_time_job=one_time_job).count(), 0)

    def test_a_serial_that_would_restructure_the_key_is_neutralised(self):
        # the serial is whatever the agent said it was, and it lands in the object key: a "/" in it
        # would move the object to a prefix of the agent's choosing
        configuration = force_configuration()
        _, _, token = force_enrolled_machine(configuration=configuration,
                                             meta_business_unit=self.mbu,
                                             serial_number="../../etc/passwd")
        command = force_command(backend=CommandBackend.SYSDIAGNOSE)
        one_time_job = force_one_time_job(configuration=configuration, job=command.job)
        key = self._mint(token, self._body(one_time_job)).json()["key"]
        self.assertTrue(key.startswith("turbo/uploads/.._.._etc_passwd/"))
        # still exactly the segments the server builds: turbo/uploads/<serial>/<schedule>/<row>/<file>
        self.assertEqual(len(key.split("/")), 6)

    def test_a_serial_of_nothing_but_dots_is_not_a_traversal_segment(self):
        # dots survive the substitution, so ".." alone would climb a directory on the filesystem
        # storage the hosted fallback writes to
        configuration = force_configuration()
        _, _, token = force_enrolled_machine(configuration=configuration,
                                             meta_business_unit=self.mbu, serial_number="..")
        command = force_command(backend=CommandBackend.SYSDIAGNOSE)
        one_time_job = force_one_time_job(configuration=configuration, job=command.job)
        key = self._mint(token, self._body(one_time_job)).json()["key"]
        self.assertTrue(key.startswith("turbo/uploads/unknown/"))

    def test_mint_unknown_kind(self):
        # during a rolling deploy an older instance can read a Job a newer one wrote. Its definition
        # is unreachable, so it declares no artifact and the mint has nothing to sign.
        configuration, serial_number, token = self._enrolled()
        future_job = Job.objects.create(kind="a_kind_from_the_future")
        one_time_job = force_one_time_job(configuration=configuration, job=future_job,
                                          serial_numbers=[serial_number])
        response = self._mint(token, self._body(one_time_job))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "unknown_artifact"})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_upload_str(self, post_event):
        configuration, serial_number, token = self._enrolled()
        _, one_time_job = self._scheduled_command(configuration=configuration,
                                                  serial_number=serial_number)
        run_id = uuid.uuid4()
        self._mint(token, self._body(one_time_job, run_id=run_id))
        upload = JobUpload.objects.get(run_id=run_id)
        self.assertEqual(str(upload), f"archive of {run_id} on {serial_number}")


class TurboPresignedMintTestCase(TurboPublicTestCase):
    """The mint against a storage that can sign, which is what every S3 deployment does.

    The other classes exercise the hosted fallback, because that is what the test settings use — so
    without this the production branch is reached by nothing.
    """

    @override_settings(STORAGES=S3_STORAGE)
    def test_the_mint_hands_back_a_presigned_put(self):
        configuration = force_configuration()
        _, serial_number, token = force_enrolled_machine(configuration=configuration,
                                                         meta_business_unit=self.mbu)
        command = force_command(backend=CommandBackend.SYSDIAGNOSE)
        one_time_job = force_one_time_job(configuration=configuration, job=command.job,
                                          serial_numbers=[serial_number])
        response = self.client.post(
            reverse("turbo_public:uploads"),
            data=json.dumps({"schedule_pk": str(one_time_job.pk), "run_id": str(uuid.uuid4()),
                             "artifact": "archive", "size": 1024, "sha256": SHA256}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}")
        self.assertEqual(response.status_code, 200)
        answer = response.json()
        self.assertEqual(answer["mode"], "put")
        # straight at the bucket, not back at us: Zentral never sees the bytes
        self.assertTrue(answer["url"].startswith("https://zentral-tests.s3.amazonaws.com/"))
        self.assertIn("X-Amz-Signature", answer["url"])
        self.assertEqual(answer["headers"]["Content-Length"], "1024")
        self.assertEqual(answer["headers"]["Content-Type"], "application/gzip")
        self.assertIn("x-amz-checksum-sha256", answer["headers"])
        # and the ceiling published to that machine is the presigned one, not the worker's
        config = self.client.get(reverse("turbo_public:config"),
                                 HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}").json()
        self.assertEqual(config["upload_max_size"], 2 * 2**30)
        self.assertEqual(config["upload_digests"], ["crc64nvme"])


class TurboHostedUploadTestCase(TurboPublicTestCase):
    def _upload(self, one_time_job, serial_number, body=b"yolo"):
        # the row describes the bytes it expects: the destination checks both the length and the
        # digest, which is all a filesystem storage will ever be able to say about them
        return JobUpload.objects.create(
            schedule_pk=one_time_job.pk, schedule_mode="one_time", serial_number=serial_number,
            run_id=uuid.uuid4(), artifact="archive", key="turbo/uploads/test/archive.tar.gz",
            size=len(body), sha256=hashlib.sha256(body).hexdigest(),
        )

    def test_a_forged_token_is_refused(self):
        response = self.client.put(reverse("turbo_public:upload", args=("not-a-token",)),
                                   data=b"body", content_type="application/gzip")
        self.assertEqual(response.status_code, 403)

    def test_the_body_lands_at_the_minted_key(self):
        configuration = force_configuration()
        _, serial_number, _ = force_enrolled_machine(configuration=configuration,
                                                     meta_business_unit=self.mbu)
        one_time_job = force_one_time_job(configuration=configuration)
        upload = self._upload(one_time_job, serial_number)
        response = self.client.put(
            reverse("turbo_public:upload", args=(sign_hosted_upload(upload),)),
            data=b"yolo", content_type="application/gzip")
        self.assertEqual(response.status_code, 200)
        storage = storages["default"]
        self.assertTrue(storage.exists(upload.key))
        with storage.open(upload.key) as f:
            self.assertEqual(f.read(), b"yolo")
        storage.delete(upload.key)

    def test_a_second_body_overwrites_at_the_same_key(self):
        # the key is stable, so storage.save() picking a free name instead would silently detach the
        # object from the row that names it
        configuration = force_configuration()
        _, serial_number, _ = force_enrolled_machine(configuration=configuration,
                                                     meta_business_unit=self.mbu)
        one_time_job = force_one_time_job(configuration=configuration)
        # what is being tested here is the key, not the body, so both writes carry bytes the row
        # accepts — a retry that re-signs the same key re-declares the same digest with it
        upload = self._upload(one_time_job, serial_number, body=b"first!")
        url = reverse("turbo_public:upload", args=(sign_hosted_upload(upload),))
        self.client.put(url, data=b"first!", content_type="application/gzip")
        upload.sha256 = hashlib.sha256(b"second").hexdigest()
        upload.save()
        self.client.put(url, data=b"second", content_type="application/gzip")
        storage = storages["default"]
        with storage.open(upload.key) as f:
            self.assertEqual(f.read(), b"second")
        storage.delete(upload.key)


class TurboHostedUploadLimitTestCase(TurboPublicTestCase):
    """What the hosted destination does at the wall, where a presigned PUT has the storage to lean on."""

    def _minted(self, body=BODY):
        configuration = force_configuration()
        _, serial_number, token = force_enrolled_machine(configuration=configuration,
                                                         meta_business_unit=self.mbu)
        command = force_command(backend=CommandBackend.SYSDIAGNOSE)
        one_time_job = force_one_time_job(configuration=configuration, job=command.job,
                                          serial_numbers=[serial_number])
        minted = self.client.post(
            reverse("turbo_public:uploads"),
            data=json.dumps({"schedule_pk": str(one_time_job.pk), "run_id": str(uuid.uuid4()),
                             "artifact": "archive", "size": len(body),
                             "sha256": hashlib.sha256(body).hexdigest()}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}").json()
        return JobUpload.objects.get(key=minted["key"])

    def _put(self, upload, body):
        return self.client.put(
            reverse("turbo_public:upload", args=(sign_hosted_upload(upload),)),
            data=body, content_type="application/octet-stream")

    def test_a_body_over_the_deployment_limit_is_json_not_html(self):
        # Django answers a SuspiciousOperation with an HTML error page, on the one endpoint
        # contracted never to serve one — and the agent burns every retry parsing it
        upload = self._minted(b"x" * 4096)
        with self.settings(DATA_UPLOAD_MAX_MEMORY_SIZE=1024):
            response = self._put(upload, b"x" * 4096)
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertEqual(response.json(), {"error": "too_large"})

    def test_a_body_that_is_not_the_declared_size(self):
        # a presigned PUT has the length in the signature and the storage enforces it; here there is
        # nobody else to do it, and the size is what the mint clamped against
        upload = self._minted(b"x" * 1024)
        response = self._put(upload, b"x" * 512)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "size_mismatch"})
        self.assertFalse(storages["default"].exists(upload.key))

    def test_a_body_of_the_right_length_and_the_wrong_bytes(self):
        # the case the length cannot catch, and the only point where a filesystem storage can: it
        # reports no checksum, so the verification axis will have nothing to read back on this path
        upload = self._minted(b"x" * 1024)
        response = self._put(upload, b"y" * 1024)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "digest_mismatch"})
        self.assertFalse(storages["default"].exists(upload.key))

    def test_a_token_naming_an_upload_that_is_gone(self):
        upload = self._minted()
        token = sign_hosted_upload(upload)
        upload.delete()
        response = self.client.put(reverse("turbo_public:upload", args=(token,)), data=b"")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {"error": "unknown_upload"})

    def test_a_second_upload_of_a_closed_row(self):
        upload = self._minted()
        upload.status = UploadStatus.UPLOADED
        upload.save()
        response = self._put(upload, BODY)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json(), {"error": "already_uploaded"})

    def test_every_refusal_answers_json(self):
        upload = self._minted()
        for response, expected in (
            (self.client.put(reverse("turbo_public:upload", args=("forged",)), data=b""),
             (403, {"error": "invalid_token"})),
            (self._put(upload, BODY), (200, {})),
            (self._put(upload, BODY), (200, {})),
        ):
            self.assertEqual(response.status_code, expected[0])
            self.assertEqual(response["Content-Type"], "application/json")
            self.assertEqual(response.json(), expected[1])


class TurboUploadConfigTestCase(TurboPublicTestCase):
    def test_the_config_publishes_the_deployment_knobs(self):
        # so the agent fails fast instead of compressing an artifact it cannot send, and hashes once
        configuration = force_configuration()
        _, serial_number, token = force_enrolled_machine(configuration=configuration,
                                                         meta_business_unit=self.mbu)
        response = self.client.get(reverse("turbo_public:config"),
                                   HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}")
        self.assertEqual(response.status_code, 200)
        answer = response.json()
        self.assertIn("upload_max_size", answer)
        self.assertIn("upload_digests", answer)
        # no part size: nothing the agent computes depends on the chunk geometry
        self.assertNotIn("upload_part_size", answer)

    def test_the_published_ceiling_is_the_one_the_deployment_enforces(self):
        # the published number is a promise the agent spends an artifact and five retries on. Without
        # a presigned storage the body comes through the workers, and the wall it meets there is
        # DATA_UPLOAD_MAX_MEMORY_SIZE — so that is the number, not one of our choosing.
        configuration = force_configuration()
        _, serial_number, token = force_enrolled_machine(configuration=configuration,
                                                         meta_business_unit=self.mbu)
        with self.settings(DATA_UPLOAD_MAX_MEMORY_SIZE=10485760):
            answer = self.client.get(reverse("turbo_public:config"),
                                     HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}").json()
        self.assertEqual(answer["upload_max_size"], 10485760)

    def test_a_deployment_that_declares_no_body_limit(self):
        # Django lets the limit be disabled, and min(int, None) is a TypeError — a 500 on the same
        # endpoint, from the same habit of trusting a setting to be a number
        configuration = force_configuration()
        _, serial_number, token = force_enrolled_machine(configuration=configuration,
                                                         meta_business_unit=self.mbu)
        with self.settings(DATA_UPLOAD_MAX_MEMORY_SIZE=None):
            answer = self.client.get(reverse("turbo_public:config"),
                                     HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}").json()
            # the shipped nginx configurations cap at 10 MiB, so publishing more would be the same
            # invisible wall again — a deployment that raised its proxy can raise Django's too
            self.assertEqual(answer["upload_max_size"], 10 * 2**20)
            command = force_command(backend=CommandBackend.SYSDIAGNOSE)
            one_time_job = force_one_time_job(configuration=configuration, job=command.job,
                                              serial_numbers=[serial_number])
            response = self.client.post(
                reverse("turbo_public:uploads"),
                data=json.dumps({"schedule_pk": str(one_time_job.pk), "run_id": str(uuid.uuid4()),
                                 "artifact": "archive", "size": 11 * 2**20, "sha256": SHA256}),
                content_type="application/json",
                HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}")
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json(), {"error": "too_large"})

    def test_the_mint_refuses_what_the_ceiling_promised_against(self):
        # the same number on both endpoints, so an oversize artifact is refused before any bytes move
        configuration = force_configuration()
        _, serial_number, token = force_enrolled_machine(configuration=configuration,
                                                         meta_business_unit=self.mbu)
        command = force_command(backend=CommandBackend.SYSDIAGNOSE)
        one_time_job = force_one_time_job(configuration=configuration, job=command.job,
                                          serial_numbers=[serial_number])
        with self.settings(DATA_UPLOAD_MAX_MEMORY_SIZE=10485760):
            response = self.client.post(
                reverse("turbo_public:uploads"),
                data=json.dumps({"schedule_pk": str(one_time_job.pk), "run_id": str(uuid.uuid4()),
                                 "artifact": "archive", "size": 10485761, "sha256": SHA256}),
                content_type="application/json",
                HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}")
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json(), {"error": "too_large"})


class TurboUploadIngestTestCase(TurboPublicTestCase):
    """The other half of the round trip: result.uploads[] closes the row, on the agent's word.

    Whether the storage agrees is a second axis, decided later — nothing here reads an object.
    """

    def _results(self, token, body):
        return self.client.post(
            reverse("turbo_public:results"),
            data=json.dumps(body),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}",
        )

    def _mint(self, token, one_time_job, run_id, artifact):
        return self.client.post(
            reverse("turbo_public:uploads"),
            data=json.dumps({"schedule_pk": str(one_time_job.pk), "run_id": str(run_id),
                             "artifact": artifact, "size": 1024, "sha256": SHA256}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}",
        ).json()

    def _minted(self, artifact="archive", backend=CommandBackend.SYSDIAGNOSE):
        configuration = force_configuration()
        _, serial_number, token = force_enrolled_machine(configuration=configuration,
                                                         meta_business_unit=self.mbu)
        command = force_command(backend=backend)
        one_time_job = force_one_time_job(configuration=configuration, job=command.job,
                                          serial_numbers=[serial_number])
        run_id = uuid.uuid4()
        return token, one_time_job, run_id, self._mint(token, one_time_job, run_id, artifact)

    @staticmethod
    def _result(one_time_job, run_id, uploads):
        return {"results": [{"kind": one_time_job.job.kind, "pk": str(one_time_job.job.pk),
                             "version": one_time_job.job.version,
                             "run": {"at": "2026-09-03T10:00:00Z", "duration": 1.0,
                                     "schedule_pk": str(one_time_job.pk), "id": str(run_id),
                                     "mode": "one_time"},
                             "result": {"exit_code": 0, "uploads": uploads}}]}

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_a_reported_upload_closes_the_row(self, post_event):
        token, one_time_job, run_id, minted = self._minted()
        response = self._results(token, self._result(one_time_job, run_id, [
            {"artifact": "archive", "key": minted["key"], "size": 1024, "sha256": SHA256}]))
        self.assertEqual(response.status_code, 200)
        upload = JobUpload.objects.get(run_id=run_id)
        self.assertEqual(upload.status, UploadStatus.UPLOADED)
        self.assertIsNotNone(upload.completed_at)
        # the second axis is untouched: nothing here asked the storage anything
        self.assertEqual(upload.verification, "pending")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_a_reported_failure_closes_the_row_as_failed(self, post_event):
        token, one_time_job, run_id, minted = self._minted()
        self._results(token, self._result(one_time_job, run_id, [
            {"artifact": "archive",
             "error": {"reason": "http_status", "attempts": 5, "last_http_status": 403}}]))
        upload = JobUpload.objects.get(run_id=run_id)
        self.assertEqual(upload.status, UploadStatus.FAILED)
        self.assertEqual(upload.error_reason, "http_status")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_an_unknown_error_reason_still_closes_the_row(self, post_event):
        # the reason is the agent's, and a value this release does not know must not stop the row
        # being closed — the artifact is not coming
        token, one_time_job, run_id, minted = self._minted()
        self._results(token, self._result(one_time_job, run_id, [
            {"artifact": "archive", "error": {"reason": "sunspots"}}]))
        upload = JobUpload.objects.get(run_id=run_id)
        self.assertEqual(upload.status, UploadStatus.FAILED)
        self.assertIsNone(upload.error_reason)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_an_echoed_key_that_does_not_match_is_not_accepted(self, post_event):
        # the server never takes a key from the wire — it compares. An echo that differs is the agent
        # talking about a different object than the one we signed.
        token, one_time_job, run_id, minted = self._minted()
        self._results(token, self._result(one_time_job, run_id, [
            {"artifact": "archive", "key": "turbo/uploads/somewhere/else", "size": 1024}]))
        upload = JobUpload.objects.get(run_id=run_id)
        self.assertEqual(upload.status, UploadStatus.FAILED)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_partial_success_is_first_class(self, post_event):
        # file_export uploads its manifest and gives up on the archive: the inventory of what was
        # collected survives the archive that never made it
        configuration = force_configuration()
        _, serial_number, token = force_enrolled_machine(configuration=configuration,
                                                         meta_business_unit=self.mbu)
        command = force_command(backend=CommandBackend.FILE_EXPORT)
        one_time_job = force_one_time_job(configuration=configuration, job=command.job,
                                          serial_numbers=[serial_number])
        run_id = uuid.uuid4()
        keys = {artifact: self._mint(token, one_time_job, run_id, artifact)["key"]
                for artifact in ("manifest", "archive")}
        self._results(token, self._result(one_time_job, run_id, [
            {"artifact": "manifest", "key": keys["manifest"], "size": 1024, "sha256": SHA256},
            {"artifact": "archive", "error": {"reason": "network", "attempts": 5}}]))
        rows = {row.artifact: row for row in JobUpload.objects.filter(run_id=run_id)}
        self.assertEqual(rows["manifest"].status, UploadStatus.UPLOADED)
        self.assertEqual(rows["archive"].status, UploadStatus.FAILED)
        self.assertEqual(rows["archive"].error_reason, "network")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_an_optional_artifact_that_was_never_minted_is_not_missing(self, post_event):
        # a file_export that matched nothing has no archive, and an empty archive would be a fiction.
        # The plane never expected one: minting is per artifact, so an artifact that did not happen
        # leaves no row to be pending forever.
        configuration = force_configuration()
        _, serial_number, token = force_enrolled_machine(configuration=configuration,
                                                         meta_business_unit=self.mbu)
        command = force_command(backend=CommandBackend.FILE_EXPORT)
        one_time_job = force_one_time_job(configuration=configuration, job=command.job,
                                          serial_numbers=[serial_number])
        run_id = uuid.uuid4()
        key = self._mint(token, one_time_job, run_id, "manifest")["key"]
        self._results(token, self._result(one_time_job, run_id, [
            {"artifact": "manifest", "key": key, "size": 1024, "sha256": SHA256}]))
        rows = list(JobUpload.objects.filter(run_id=run_id))
        self.assertEqual([(row.artifact, row.status) for row in rows],
                         [("manifest", UploadStatus.UPLOADED)])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_truncated_rides_the_artifact_entry(self, post_event):
        token, one_time_job, run_id, minted = self._minted(backend=CommandBackend.FILE_EXPORT)
        self._results(token, self._result(one_time_job, run_id, [
            {"artifact": "archive", "key": minted["key"], "size": 1024, "sha256": SHA256,
             "truncated": True}]))
        self.assertTrue(JobUpload.objects.get(run_id=run_id).truncated)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_uploads_without_a_run_id_are_ignored(self, post_event):
        # the rows are keyed by run: without one there is nothing to match on, and the entry is still
        # accepted because the run did happen
        token, one_time_job, run_id, minted = self._minted()
        body = self._result(one_time_job, run_id, [
            {"artifact": "archive", "key": minted["key"], "size": 1024}])
        del body["results"][0]["run"]["id"]
        response = self._results(token, body)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()["accepted"]), 1)
        self.assertEqual(JobUpload.objects.get(run_id=run_id).status, UploadStatus.PENDING)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_an_artifact_that_was_never_minted_is_ignored(self, post_event):
        token, one_time_job, run_id, minted = self._minted()
        response = self._results(token, self._result(one_time_job, run_id, [
            {"artifact": "invented", "key": "whatever", "size": 1}]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()["accepted"]), 1)
        self.assertEqual(JobUpload.objects.get(run_id=run_id).status, UploadStatus.PENDING)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_a_malformed_uploads_entry_never_fails_the_batch(self, post_event):
        token, one_time_job, run_id, minted = self._minted()
        response = self._results(token, self._result(one_time_job, run_id, ["not-a-dict"]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()["accepted"]), 1)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_a_closed_row_is_not_reopened_by_a_second_result(self, post_event):
        token, one_time_job, run_id, minted = self._minted()
        success = self._result(one_time_job, run_id, [
            {"artifact": "archive", "key": minted["key"], "size": 1024, "sha256": SHA256}])
        self._results(token, success)
        self._results(token, self._result(one_time_job, run_id, [
            {"artifact": "archive", "error": {"reason": "network"}}]))
        self.assertEqual(JobUpload.objects.get(run_id=run_id).status, UploadStatus.UPLOADED)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_two_runs_of_one_shot_across_a_version_bump(self, post_event):
        # a version bump re-arms a one-time job, so one machine can hold two runs of one shot, each
        # with its own upload — and BOTH results have to land. A unique index over the uploaded rows
        # of a one-time schedule made the second one an IntegrityError, which ATOMIC_REQUESTS turns
        # into a 500 on the whole batch, on every retry, until someone deletes a row by hand.
        configuration = force_configuration()
        _, serial_number, token = force_enrolled_machine(configuration=configuration,
                                                         meta_business_unit=self.mbu)
        command = force_command(backend=CommandBackend.SYSDIAGNOSE)
        one_time_job = force_one_time_job(configuration=configuration, job=command.job,
                                          serial_numbers=[serial_number])
        first_run, second_run = uuid.uuid4(), uuid.uuid4()
        first_key = self._mint(token, one_time_job, first_run, "archive")["key"]
        # the operator edits the command: the version moves, and the job is served again
        command.job.version += 1
        command.job.save()
        second_key = self._mint(token, one_time_job, second_run, "archive")["key"]

        first = self._results(token, self._result(one_time_job, first_run, [
            {"artifact": "archive", "key": first_key, "size": 1024, "sha256": SHA256}]))
        self.assertEqual(first.status_code, 200)
        second = self._results(token, self._result(one_time_job, second_run, [
            {"artifact": "archive", "key": second_key, "size": 1024, "sha256": SHA256}]))
        self.assertEqual(second.status_code, 200)
        self.assertEqual(
            {str(row.run_id) for row in JobUpload.objects.filter(status=UploadStatus.UPLOADED)},
            {str(first_run), str(second_run)})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_the_gate_closes_and_a_later_mint_is_refused(self, post_event):
        # the round trip, end to end: mint, report, and the shot is spent
        token, one_time_job, run_id, minted = self._minted()
        self._results(token, self._result(one_time_job, run_id, [
            {"artifact": "archive", "key": minted["key"], "size": 1024, "sha256": SHA256}]))
        self.assertTrue(OneTimeJobMachine.objects.filter(
            one_time_job=one_time_job, last_result_at__isnull=False).exists())
        response = self.client.post(
            reverse("turbo_public:uploads"),
            data=json.dumps({"schedule_pk": str(one_time_job.pk), "run_id": str(uuid.uuid4()),
                             "artifact": "archive", "size": 1024, "sha256": SHA256}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}",
        )
        self.assertEqual(response.status_code, 410)
        self.assertEqual(response.json(), {"error": "gate_closed"})

import json
import uuid
from unittest.mock import patch

from botocore.exceptions import ClientError
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from zentral.contrib.turbo.command_backends import CommandBackend
from zentral.contrib.turbo.models import (JobUpload, UploadMode, UploadStatus, UploadVerification)
from zentral.contrib.turbo.tasks import abort_multipart_upload_task, complete_multipart_upload_task

from .utils import (TurboPublicTestCase, force_command, force_configuration, force_enrolled_machine,
                    force_one_time_job)


SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
CRC = "nD+hB17SSLE="
S3_STORAGE = {"default": {"BACKEND": "storages.backends.s3.S3Storage",
                          "OPTIONS": {"bucket_name": "zentral-tests",
                                      "access_key": "AKIAIOSFODNN7EXAMPLE",
                                      "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                                      "region_name": "us-east-1"}}}
PARTS = [{"PartNumber": 1, "ETag": '"e1"'}, {"PartNumber": 2, "ETag": '"e2"'}]


def client_error(code, operation="CompleteMultipartUpload"):
    return ClientError({"Error": {"Code": code, "Message": code}}, operation)


class TurboUploadCompleteViewTestCase(TurboPublicTestCase):
    """`POST uploads/complete/` — the agent says the parts are up, and the server takes it from there.

    202 and not 200: both storages document that assembling a multipart upload can take several
    minutes, so it cannot sit in a device request, and the agent has no use for the answer anyway.
    """

    def _upload(self, mode=UploadMode.MULTIPART, upload_id="mpu-1",
                verification=UploadVerification.PENDING):
        configuration = force_configuration()
        _, serial_number, token = force_enrolled_machine(configuration=configuration,
                                                         meta_business_unit=self.mbu)
        command = force_command(backend=CommandBackend.SYSDIAGNOSE)
        one_time_job = force_one_time_job(configuration=configuration, job=command.job,
                                          serial_numbers=[serial_number])
        upload = JobUpload.objects.create(
            schedule_pk=one_time_job.pk, schedule_mode="one_time", serial_number=serial_number,
            run_id=uuid.uuid4(), artifact="archive", key="turbo/uploads/test/archive.tar.gz",
            size=200, sha256=SHA256, crc64nvme=CRC, mode=mode, upload_id=upload_id,
            part_size=100, status=UploadStatus.UPLOADED, verification=verification,
        )
        return token, one_time_job, upload

    def _complete(self, token, one_time_job, upload, **overrides):
        body = {"schedule_pk": str(one_time_job.pk), "run_id": str(upload.run_id),
                "artifact": upload.artifact, **overrides}
        return self.client.post(
            reverse("turbo_public:uploads_complete"),
            data=json.dumps(body),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}",
        )

    def test_unauthenticated(self):
        response = self.client.post(reverse("turbo_public:uploads_complete"), data="{}",
                                    content_type="application/json")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"error": "unauthenticated"})

    @patch("zentral.contrib.turbo.public_views.uploads.complete_multipart_upload_task")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_the_call_is_accepted_and_the_work_is_queued(self, post_event, task):
        token, one_time_job, upload = self._upload()
        with self.captureOnCommitCallbacks(execute=True):
            response = self._complete(token, one_time_job, upload)
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json(), {})
        task.apply_async.assert_called_once_with((str(upload.pk),))

    @patch("zentral.contrib.turbo.public_views.uploads.complete_multipart_upload_task")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_the_request_event_is_posted_on_the_202(self, post_event, task):
        # the event records that the agent made the request; an endpoint that only accepts the work
        # still made a request
        from zentral.contrib.turbo.events import TurboRequestEvent
        token, one_time_job, upload = self._upload()
        with self.captureOnCommitCallbacks(execute=True):
            self._complete(token, one_time_job, upload)
        events = [c.args[0] for c in post_event.call_args_list
                  if isinstance(c.args[0], TurboRequestEvent)]
        self.assertEqual([e.payload["request_type"] for e in events], ["upload_complete"])

    @patch("zentral.contrib.turbo.public_views.uploads.complete_multipart_upload_task")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_an_already_verified_upload_queues_nothing(self, post_event, task):
        token, one_time_job, upload = self._upload(verification=UploadVerification.VERIFIED)
        with self.captureOnCommitCallbacks(execute=True):
            response = self._complete(token, one_time_job, upload)
        self.assertEqual(response.status_code, 202)
        task.apply_async.assert_not_called()

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_an_unknown_upload(self, post_event):
        token, one_time_job, upload = self._upload()
        response = self._complete(token, one_time_job, upload, run_id=str(uuid.uuid4()))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "unknown_upload"})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_another_machine_s_upload_is_unknown(self, post_event):
        # the row is looked up by the AUTHENTICATED serial: without that a machine could complete
        # another machine's upload
        _, one_time_job, upload = self._upload()
        _, _, other_token = force_enrolled_machine(configuration=one_time_job.configuration,
                                                   meta_business_unit=self.mbu)
        response = self._complete(other_token, one_time_job, upload)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "unknown_upload"})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_a_single_put_is_not_multipart(self, post_event):
        # a single PUT is finished when its PUT returns, and `mode` is how the agent knows which it
        # has: asking for this is a contract error, not a transient one
        token, one_time_job, upload = self._upload(mode=UploadMode.PUT, upload_id="")
        response = self._complete(token, one_time_job, upload)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "not_multipart"})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_a_missing_artifact(self, post_event):
        token, one_time_job, upload = self._upload()
        response = self._complete(token, one_time_job, upload, artifact="")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "missing_artifact"})


@override_settings(STORAGES=S3_STORAGE)
class TurboCompleteMultipartTaskTestCase(TurboPublicTestCase):
    """The assembly, and what each answer from the storage means for the verification axis."""

    def _upload(self, **overrides):
        attributes = {"schedule_pk": uuid.uuid4(), "schedule_mode": "one_time",
                      "serial_number": "C02ZTEST", "run_id": uuid.uuid4(), "artifact": "archive",
                      "key": "turbo/uploads/test/archive.tar.gz", "size": 200, "sha256": SHA256,
                      "crc64nvme": CRC, "mode": UploadMode.MULTIPART, "upload_id": "mpu-1",
                      "part_size": 100, "status": UploadStatus.UPLOADED}
        attributes.update(overrides)
        return JobUpload.objects.create(**attributes)

    @patch("zentral.contrib.turbo.tasks.complete_multipart_upload")
    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_a_completed_assembly_is_verified(self, list_parts, complete):
        list_parts.return_value = PARTS
        upload = self._upload()
        result = complete_multipart_upload_task(str(upload.pk))
        self.assertEqual(result["status"], "completed")
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.VERIFIED)
        self.assertIsNotNone(upload.verified_at)
        # the part list is the STORAGE's, and the checksum is the one the agent declared at the mint
        complete.assert_called_once()
        args, kwargs = complete.call_args
        self.assertEqual(args[2], PARTS)
        self.assertEqual(args[3], CRC)
        self.assertEqual(args[4], 200)

    @patch("zentral.contrib.turbo.tasks.complete_multipart_upload")
    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_a_bad_digest_is_an_assembly_failure(self, list_parts, complete):
        # the whole point of declaring the algorithm at create: S3 computes the assembled object's
        # own checksum and refuses a mismatch
        list_parts.return_value = PARTS
        complete.side_effect = client_error("BadDigest")
        upload = self._upload()
        with self.assertLogs("zentral.contrib.turbo.tasks", level="ERROR"):
            result = complete_multipart_upload_task(str(upload.pk))
        self.assertEqual(result["error"], "BadDigest")
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.ASSEMBLY_FAILED)
        # and the first axis is untouched: the agent did upload, and the shot stays spent
        self.assertEqual(upload.status, UploadStatus.UPLOADED)

    @patch("zentral.contrib.turbo.tasks.complete_multipart_upload")
    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_no_parts_at_all_is_an_assembly_failure(self, list_parts, complete):
        # the agent said every part was up and the storage holds none: either they aged out on the
        # lifecycle rule or they were never there
        list_parts.return_value = []
        upload = self._upload()
        result = complete_multipart_upload_task(str(upload.pk))
        self.assertEqual(result["status"], "no_parts")
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.ASSEMBLY_FAILED)
        complete.assert_not_called()

    @patch("zentral.contrib.turbo.tasks.stat_object")
    @patch("zentral.contrib.turbo.tasks.complete_multipart_upload")
    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_completing_an_already_completed_upload_is_success(self, list_parts, complete, stat):
        # NoSuchUpload is what the storage says both for an upload that completed already and for one
        # whose parts were aborted. The object is the only thing that tells them apart — and a retry
        # of the agent's call is exactly how the first case arrives here.
        list_parts.side_effect = client_error("NoSuchUpload", "ListParts")
        stat.return_value = {"size": 200, "sha256": None, "crc64nvme": CRC}
        upload = self._upload()
        result = complete_multipart_upload_task(str(upload.pk))
        self.assertEqual(result["status"], "already_completed")
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.VERIFIED)

    @patch("zentral.contrib.turbo.tasks.stat_object")
    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_parts_gone_with_no_object_is_an_assembly_failure(self, list_parts, stat):
        list_parts.side_effect = client_error("NoSuchUpload", "ListParts")
        stat.return_value = None
        upload = self._upload()
        result = complete_multipart_upload_task(str(upload.pk))
        self.assertEqual(result["status"], "parts_gone")
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.ASSEMBLY_FAILED)

    @patch("zentral.contrib.turbo.tasks.stat_object")
    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_a_storage_that_cannot_be_asked_is_retried(self, list_parts, stat):
        # the upload id is gone and the object is the only thing that says whether that means
        # "completed" or "aborted". Without an answer there is nothing to record, so the row keeps
        # waiting rather than being called either.
        list_parts.side_effect = client_error("NoSuchUpload", "ListParts")
        stat.side_effect = Exception("the storage is having a day")
        upload = self._upload()
        with patch.object(complete_multipart_upload_task, "retry",
                          side_effect=RuntimeError("retried")) as retry:
            with self.assertLogs("zentral.contrib.turbo.tasks", level="ERROR"):
                with self.assertRaises(RuntimeError):
                    complete_multipart_upload_task(str(upload.pk))
        self.assertEqual(retry.call_count, 1)
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.PENDING)

    @patch("zentral.contrib.turbo.tasks.stat_object")
    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_an_object_of_the_wrong_size_is_not_an_already_completed_upload(self, list_parts, stat):
        list_parts.side_effect = client_error("NoSuchUpload", "ListParts")
        stat.return_value = {"size": 17, "sha256": None, "crc64nvme": None}
        upload = self._upload()
        result = complete_multipart_upload_task(str(upload.pk))
        self.assertEqual(result["status"], "parts_gone")
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.ASSEMBLY_FAILED)

    @patch("zentral.contrib.turbo.tasks.stat_object")
    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_the_crc_settles_it_where_the_size_would_only_agree(self, list_parts, stat):
        # the right size and somebody else's bytes: the HEAD reports the whole-object CRC the
        # completion validated, and the row holds the one the agent declared, so the match is exact
        list_parts.side_effect = client_error("NoSuchUpload", "ListParts")
        stat.return_value = {"size": 200, "sha256": None, "crc64nvme": "AAAAAAAAAAA="}
        upload = self._upload()
        self.assertEqual(complete_multipart_upload_task(str(upload.pk))["status"], "parts_gone")
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.ASSEMBLY_FAILED)

    @patch("zentral.contrib.turbo.tasks.stat_object")
    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_a_matching_crc_is_the_completed_object(self, list_parts, stat):
        list_parts.side_effect = client_error("NoSuchUpload", "ListParts")
        stat.return_value = {"size": 999, "sha256": None, "crc64nvme": CRC}
        upload = self._upload()
        # the CRC decides, so a size that disagrees does not
        self.assertEqual(complete_multipart_upload_task(str(upload.pk))["status"],
                         "already_completed")
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.VERIFIED)

    @patch("zentral.contrib.turbo.tasks.complete_multipart_upload")
    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_a_transient_error_is_retried(self, list_parts, complete):
        # a storage that is throttling or unreachable improves by asking again, with backoff. Nothing
        # is recorded on the axis in the meantime — the row stays pending, which is honest.
        # asserted on the task's own retry rather than on a result state: celery re-raises the
        # original exception for a direct call and records eager retries as failures, so neither
        # tells a retry from a give-up.
        list_parts.return_value = PARTS
        complete.side_effect = client_error("SlowDown")
        upload = self._upload()
        with patch.object(complete_multipart_upload_task, "retry",
                          side_effect=RuntimeError("retried")) as retry:
            with self.assertRaises(RuntimeError):
                complete_multipart_upload_task(str(upload.pk))
        self.assertEqual(retry.call_count, 1)
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.PENDING)

    @patch("zentral.contrib.turbo.tasks.complete_multipart_upload")
    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_a_result_that_lands_during_the_assembly_survives_it(self, list_parts, complete):
        # the normal sequence, and the storage calls are given the window the docs allow: the task
        # loads the row, the agent's result closes the status axis while ListParts and
        # CompleteMultipartUpload run, and the task must not write its stale copy back over that. A
        # full save here returned the row to pending for good — the agent was acknowledged and never
        # resends — so it kept counting against MAX_PENDING_UPLOADS and read as a report that never
        # came.
        upload = self._upload(status=UploadStatus.PENDING)
        list_parts.return_value = PARTS

        def the_result_arrives(*args, **kwargs):
            JobUpload.objects.filter(pk=upload.pk).update(
                status=UploadStatus.UPLOADED, truncated=True, completed_at=timezone.now())
            return {"ETag": '"final"'}

        complete.side_effect = the_result_arrives
        complete_multipart_upload_task(str(upload.pk))
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.VERIFIED)
        # what the ingest wrote is still there
        self.assertEqual(upload.status, UploadStatus.UPLOADED)
        self.assertTrue(upload.truncated)
        self.assertIsNotNone(upload.completed_at)

    def test_an_already_verified_upload_is_left_alone(self):
        upload = self._upload(verification=UploadVerification.VERIFIED)
        result = complete_multipart_upload_task(str(upload.pk))
        self.assertEqual(result["status"], "already_verified")

    def test_a_single_put_is_not_assembled(self):
        upload = self._upload(mode=UploadMode.PUT, upload_id="")
        with self.assertLogs("zentral.contrib.turbo.tasks", level="ERROR"):
            result = complete_multipart_upload_task(str(upload.pk))
        self.assertEqual(result["status"], "not_multipart")
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.PENDING)


@override_settings(STORAGES=S3_STORAGE)
class TurboAbortMultipartTaskTestCase(TurboPublicTestCase):
    """Giving up frees the parts, which are stored and billed until something removes them."""

    def _upload(self, **overrides):
        attributes = {"schedule_pk": uuid.uuid4(), "schedule_mode": "one_time",
                      "serial_number": "C02ZTEST", "run_id": uuid.uuid4(), "artifact": "archive",
                      "key": "turbo/uploads/test/archive.tar.gz", "size": 200, "sha256": SHA256,
                      "crc64nvme": CRC, "mode": UploadMode.MULTIPART, "upload_id": "mpu-1",
                      "part_size": 100, "status": UploadStatus.FAILED}
        attributes.update(overrides)
        return JobUpload.objects.create(**attributes)

    @patch("zentral.contrib.turbo.tasks.abort_multipart_upload")
    def test_the_parts_are_dropped(self, abort):
        upload = self._upload()
        result = abort_multipart_upload_task(str(upload.pk))
        self.assertEqual(result["status"], "aborted")
        abort.assert_called_once()

    @patch("zentral.contrib.turbo.tasks.abort_multipart_upload")
    def test_an_upload_that_is_already_gone(self, abort):
        abort.side_effect = client_error("NoSuchUpload", "AbortMultipartUpload")
        upload = self._upload()
        self.assertEqual(abort_multipart_upload_task(str(upload.pk))["status"], "aborted")

    @patch("zentral.contrib.turbo.tasks.abort_multipart_upload")
    def test_another_error_is_not_swallowed(self, abort):
        abort.side_effect = client_error("AccessDenied", "AbortMultipartUpload")
        upload = self._upload()
        with self.assertRaises(ClientError):
            abort_multipart_upload_task(str(upload.pk))

    @patch("zentral.contrib.turbo.tasks.abort_multipart_upload")
    def test_an_upload_that_is_not_failed_is_left_alone(self, abort):
        # the row moved on between the enqueue and here: an abort now would drop the parts of an
        # upload somebody is still counting on
        upload = self._upload(status=UploadStatus.UPLOADED)
        self.assertEqual(abort_multipart_upload_task(str(upload.pk))["status"], "not_failed")
        abort.assert_not_called()

    @patch("zentral.contrib.turbo.tasks.abort_multipart_upload")
    def test_a_single_put_has_nothing_to_abort(self, abort):
        upload = self._upload(mode=UploadMode.PUT, upload_id="")
        self.assertEqual(abort_multipart_upload_task(str(upload.pk))["status"], "not_multipart")
        abort.assert_not_called()


@override_settings(STORAGES=S3_STORAGE)
class TurboMultipartIngestTestCase(TurboPublicTestCase):
    """What a result means for a multipart row, which does not get HEADed.

    A multipart object is verified by its completion — the whole-object checksum validated against
    the algorithm declared at create — so there is nothing left for the ingest to ask the storage.
    What the ingest does instead is notice that a completion is still owed, or that the agent gave up.
    """

    def _minted(self, status=UploadStatus.PENDING, verification=UploadVerification.PENDING):
        configuration = force_configuration()
        _, serial_number, token = force_enrolled_machine(configuration=configuration,
                                                         meta_business_unit=self.mbu)
        command = force_command(backend=CommandBackend.SYSDIAGNOSE)
        one_time_job = force_one_time_job(configuration=configuration, job=command.job,
                                          serial_numbers=[serial_number])
        upload = JobUpload.objects.create(
            schedule_pk=one_time_job.pk, schedule_mode="one_time", serial_number=serial_number,
            run_id=uuid.uuid4(), artifact="archive", key="turbo/uploads/test/archive.tar.gz",
            size=200, sha256=SHA256, crc64nvme=CRC, mode=UploadMode.MULTIPART, upload_id="mpu-1",
            part_size=100, status=status, verification=verification,
        )
        return token, one_time_job, upload

    def _report(self, token, one_time_job, upload, entry):
        body = {"results": [{"kind": one_time_job.job.kind, "pk": str(one_time_job.job.pk),
                             "version": one_time_job.job.version,
                             "run": {"at": "2026-09-03T10:00:00Z", "duration": 1.0,
                                     "schedule_pk": str(one_time_job.pk),
                                     "id": str(upload.run_id), "mode": "one_time"},
                             "result": {"exit_code": 0, "uploads": [entry]}}]}
        return self.client.post(
            reverse("turbo_public:results"),
            data=json.dumps(body),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}",
        )

    @staticmethod
    def _uploads_ref(post_event):
        from zentral.contrib.turbo.events import TurboResultEvent
        event = [c.args[0] for c in post_event.call_args_list
                 if isinstance(c.args[0], TurboResultEvent)][0]
        return event.payload["result"]["uploads"][0]

    @patch("zentral.contrib.turbo.public_views.results.complete_multipart_upload_task")
    @patch("zentral.contrib.turbo.uploads.stat_object")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_a_completion_still_owed_is_enqueued_and_nothing_is_headed(self, post_event, stat, task):
        # the agent's own call can have been lost, and a result is often the first thing to arrive
        token, one_time_job, upload = self._minted()
        with self.captureOnCommitCallbacks(execute=True):
            response = self._report(token, one_time_job, upload,
                                    {"artifact": "archive", "key": upload.key, "size": 200,
                                     "sha256": SHA256})
        self.assertEqual(response.status_code, 200)
        task.apply_async.assert_called_once_with((str(upload.pk),))
        stat.assert_not_called()
        upload.refresh_from_db()
        self.assertEqual(upload.status, UploadStatus.UPLOADED)
        self.assertEqual(upload.verification, UploadVerification.PENDING)

    @patch("zentral.contrib.turbo.public_views.results.complete_multipart_upload_task")
    @patch("zentral.contrib.turbo.uploads.stat_object")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_an_assembled_object_rides_the_event_as_verified(self, post_event, stat, task):
        token, one_time_job, upload = self._minted(verification=UploadVerification.VERIFIED)
        with self.captureOnCommitCallbacks(execute=True):
            self._report(token, one_time_job, upload,
                         {"artifact": "archive", "key": upload.key, "size": 200, "sha256": SHA256})
        self.assertEqual(self._uploads_ref(post_event)["verification"],
                         UploadVerification.VERIFIED)
        # already answered, so there is nothing to enqueue and nothing to ask the storage
        task.apply_async.assert_not_called()
        stat.assert_not_called()

    @patch("zentral.contrib.turbo.public_views.results.complete_multipart_upload_task")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_a_failed_assembly_rides_the_event_as_not_verified(self, post_event, task):
        token, one_time_job, upload = self._minted(
            verification=UploadVerification.ASSEMBLY_FAILED)
        with self.captureOnCommitCallbacks(execute=True):
            self._report(token, one_time_job, upload,
                         {"artifact": "archive", "key": upload.key, "size": 200, "sha256": SHA256})
        # the verdict and not a boolean: assembly_failed is its own answer, and a consumer that has
        # to tell it from a mismatch cannot go to the database from an event
        self.assertEqual(self._uploads_ref(post_event)["verification"],
                         UploadVerification.ASSEMBLY_FAILED)
        task.apply_async.assert_not_called()

    @patch("zentral.contrib.turbo.public_views.results.abort_multipart_upload_task")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_a_reported_failure_frees_the_parts(self, post_event, task):
        # parts of an abandoned multipart upload are stored, and billed, until something removes
        # them. The lifecycle rule is the backstop; this is the fast path, for when the agent said so.
        token, one_time_job, upload = self._minted()
        with self.captureOnCommitCallbacks(execute=True):
            self._report(token, one_time_job, upload,
                         {"artifact": "archive", "error": {"reason": "network"}})
        task.apply_async.assert_called_once_with((str(upload.pk),))
        upload.refresh_from_db()
        self.assertEqual(upload.status, UploadStatus.FAILED)

    @patch("zentral.contrib.turbo.public_views.results.abort_multipart_upload_task")
    @patch("zentral.contrib.turbo.public_views.results.complete_multipart_upload_task")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_a_mismatched_key_frees_the_parts_too(self, post_event, complete, abort):
        # the echoed key does not match the minted one, so the row closes as failed — and a failed
        # multipart row has parts nobody will ever assemble
        token, one_time_job, upload = self._minted()
        with self.captureOnCommitCallbacks(execute=True):
            self._report(token, one_time_job, upload,
                         {"artifact": "archive", "key": "somewhere/else", "size": 200})
        abort.apply_async.assert_called_once_with((str(upload.pk),))
        complete.apply_async.assert_not_called()

import json
import uuid
from unittest.mock import patch

from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from zentral.contrib.turbo.command_backends import CommandBackend
from zentral.contrib.turbo.models import (JobUpload, UploadMode, UploadStatus, UploadVerification)
from zentral.contrib.turbo.tasks import abort_multipart_upload_task, complete_multipart_upload_task
from zentral.utils.storage import (MultipartUploadNotFound, MultipartUploadRefused, StorageError,
                                   StorageUnavailable)

from .utils import (TurboPublicTestCase, force_command, force_configuration, force_enrolled_machine,
                    force_one_time_job)


SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
CRC = "9c3fa1075ed248b1"
S3_STORAGE = {"default": {"BACKEND": "storages.backends.s3.S3Storage",
                          "OPTIONS": {"bucket_name": "zentral-tests",
                                      "access_key": "AKIAIOSFODNN7EXAMPLE",
                                      "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                                      "region_name": "us-east-1"}}}
PARTS = [{"PartNumber": 1, "ETag": '"e1"'}, {"PartNumber": 2, "ETag": '"e2"'}]


class TurboUploadCompleteViewTestCase(TurboPublicTestCase):
    """`POST uploads/complete/` — all the parts are uploaded, and the server completes the upload.

    202, not 200: the completion can take some minutes, and the agent does not wait for the result.
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

    def _complete(self, token, one_time_job, upload, run_id=None, artifact=None):
        # the run block of the mint, and the upload block with only the artifact name
        body = {"run": {"id": str(run_id or upload.run_id), "schedule_pk": str(one_time_job.pk)},
                "upload": {"artifact": upload.artifact if artifact is None else artifact}}
        return self.client.post(
            reverse("turbo_public:uploads_complete"),
            data=json.dumps(body),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}",
        )

    def test_the_flat_body_is_refused(self):
        token, one_time_job, upload = self._upload()
        response = self.client.post(
            reverse("turbo_public:uploads_complete"),
            data=json.dumps({"schedule_pk": str(one_time_job.pk), "run_id": str(upload.run_id),
                             "artifact": upload.artifact}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "missing_run"})

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

    @patch("zentral.contrib.turbo.public_views.uploads.complete_multipart_upload_task")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_a_decided_verdict_queues_nothing(self, post_event, task):
        # a decided verification is final, also a failed assembly and a mismatch
        for verification in (UploadVerification.ASSEMBLY_FAILED, UploadVerification.MISMATCH):
            with self.subTest(verification=verification):
                token, one_time_job, upload = self._upload(verification=verification)
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
        # the lookup uses the authenticated serial number, so a machine cannot complete the upload of another machine
        _, one_time_job, upload = self._upload()
        _, _, other_token = force_enrolled_machine(configuration=one_time_job.configuration,
                                                   meta_business_unit=self.mbu)
        response = self._complete(other_token, one_time_job, upload)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "unknown_upload"})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_a_single_put_is_not_multipart(self, post_event):
        # a single PUT is complete when the PUT returns. The mint response gives the mode, so this is an error of the
        # agent.
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
    """The assembly, and the verification that each answer of the storage gives."""

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
        # the parts of the storage, and the checksum that the agent declared at the mint
        complete.assert_called_once()
        args, kwargs = complete.call_args
        self.assertEqual(args[2], PARTS)
        self.assertEqual(args[3], CRC)
        self.assertEqual(args[4], 200)

    @patch("zentral.contrib.turbo.tasks.complete_multipart_upload")
    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_a_bad_digest_is_an_assembly_failure(self, list_parts, complete):
        # S3 calculates the checksum of the assembled object, and refuses an incorrect declaration
        list_parts.return_value = PARTS
        complete.side_effect = MultipartUploadRefused("BadDigest")
        upload = self._upload()
        with self.assertLogs("zentral.contrib.turbo.tasks", level="ERROR"):
            result = complete_multipart_upload_task(str(upload.pk))
        self.assertEqual(result["error"], "BadDigest")
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.ASSEMBLY_FAILED)
        # the status does not change: the agent uploaded the parts
        self.assertEqual(upload.status, UploadStatus.UPLOADED)

    @patch("zentral.contrib.turbo.tasks.complete_multipart_upload")
    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_no_parts_at_all_is_an_assembly_failure(self, list_parts, complete):
        # the agent said that all the parts are uploaded, but the storage has none: a bucket rule deleted them, or the
        # agent did not upload them
        list_parts.return_value = []
        upload = self._upload()
        result = complete_multipart_upload_task(str(upload.pk))
        self.assertEqual(result["status"], "no_parts")
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.ASSEMBLY_FAILED)
        complete.assert_not_called()

    @patch("zentral.contrib.turbo.tasks.complete_multipart_upload")
    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_missing_parts_are_reported_by_number(self, list_parts, complete):
        # the geometry of the row has two parts, and the storage has only the second. The task gives the missing part
        # number, and does not try the completion.
        list_parts.return_value = PARTS[1:]
        upload = self._upload()
        with self.assertLogs("zentral.contrib.turbo.tasks", level="ERROR"):
            result = complete_multipart_upload_task(str(upload.pk))
        self.assertEqual(result["status"], "missing_parts")
        self.assertEqual(result["missing"], [1])
        self.assertEqual(result["parts"], 1)
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.ASSEMBLY_FAILED)
        complete.assert_not_called()

    @patch("zentral.contrib.turbo.tasks.stat_object")
    @patch("zentral.contrib.turbo.tasks.complete_multipart_upload")
    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_completing_an_already_completed_upload_is_success(self, list_parts, complete, stat):
        # The storage has no upload with this id when the upload is complete, and when it is aborted. Only the object
        # shows which. A second completion call gets the first case.
        list_parts.side_effect = MultipartUploadNotFound("NoSuchUpload")
        stat.return_value = {"size": 200, "digests": {"sha256": None, "crc64nvme": CRC}}
        upload = self._upload()
        result = complete_multipart_upload_task(str(upload.pk))
        self.assertEqual(result["status"], "already_completed")
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.VERIFIED)

    @patch("zentral.contrib.turbo.tasks.stat_object")
    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_parts_gone_with_no_object_is_an_assembly_failure(self, list_parts, stat):
        list_parts.side_effect = MultipartUploadNotFound("NoSuchUpload")
        stat.return_value = None
        upload = self._upload()
        result = complete_multipart_upload_task(str(upload.pk))
        self.assertEqual(result["status"], "parts_gone")
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.ASSEMBLY_FAILED)

    @patch("zentral.contrib.turbo.tasks.stat_object")
    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_a_stat_that_cannot_answer_postpones(self, list_parts, stat):
        # no upload id, and no answer about the object: the task records nothing, and the sweep asks again
        list_parts.side_effect = MultipartUploadNotFound("NoSuchUpload")
        stat.side_effect = StorageUnavailable("503")
        upload = self._upload()
        with self.assertLogs("zentral.contrib.turbo.tasks", level="WARNING"):
            result = complete_multipart_upload_task(str(upload.pk))
        self.assertEqual(result["status"], "postponed")
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.PENDING)

    @patch("zentral.contrib.turbo.tasks.stat_object")
    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_an_object_of_the_wrong_size_is_not_an_already_completed_upload(self, list_parts, stat):
        list_parts.side_effect = MultipartUploadNotFound("NoSuchUpload")
        stat.return_value = {"size": 17, "digests": {"sha256": None, "crc64nvme": None}}
        upload = self._upload()
        result = complete_multipart_upload_task(str(upload.pk))
        self.assertEqual(result["status"], "parts_gone")
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.ASSEMBLY_FAILED)

    @patch("zentral.contrib.turbo.tasks.stat_object")
    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_the_crc_settles_it_where_the_size_would_only_agree(self, list_parts, stat):
        # the correct size, but other bytes: the CRC of the storage is not the declared CRC
        list_parts.side_effect = MultipartUploadNotFound("NoSuchUpload")
        stat.return_value = {"size": 200, "digests": {"sha256": None, "crc64nvme": "0000000000000000"}}
        upload = self._upload()
        self.assertEqual(complete_multipart_upload_task(str(upload.pk))["status"], "parts_gone")
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.ASSEMBLY_FAILED)

    @patch("zentral.contrib.turbo.tasks.stat_object")
    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_a_matching_crc_is_the_completed_object(self, list_parts, stat):
        list_parts.side_effect = MultipartUploadNotFound("NoSuchUpload")
        stat.return_value = {"size": 999, "digests": {"sha256": None, "crc64nvme": CRC}}
        upload = self._upload()
        # the CRC decides, not the size
        self.assertEqual(complete_multipart_upload_task(str(upload.pk))["status"],
                         "already_completed")
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.VERIFIED)

    @patch("zentral.contrib.turbo.tasks.complete_multipart_upload")
    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_an_unavailable_storage_postpones_the_completion(self, list_parts, complete):
        # an outage that is longer than the retries of the storage call: the row stays pending, the sweep asks again,
        # and the log is a warning
        list_parts.return_value = PARTS
        complete.side_effect = StorageUnavailable("SlowDown")
        upload = self._upload()
        with self.assertLogs("zentral.contrib.turbo.tasks", level="WARNING") as cm:
            result = complete_multipart_upload_task(str(upload.pk))
        self.assertEqual([record.levelname for record in cm.records], ["WARNING"])
        self.assertEqual(result["status"], "postponed")
        self.assertEqual(result["error"], "SlowDown")
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.PENDING)

    @patch("zentral.contrib.turbo.tasks.complete_multipart_upload")
    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_another_storage_error_postpones_and_is_an_error(self, list_parts, complete):
        # for example, a bucket policy: it stays until somebody corrects it, so the log is an error
        list_parts.side_effect = StorageError("AccessDenied")
        upload = self._upload()
        with self.assertLogs("zentral.contrib.turbo.tasks", level="ERROR"):
            result = complete_multipart_upload_task(str(upload.pk))
        self.assertEqual(result["status"], "postponed")
        complete.assert_not_called()
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.PENDING)

    @patch("zentral.contrib.turbo.tasks.complete_multipart_upload")
    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_a_result_that_lands_during_the_assembly_survives_it(self, list_parts, complete):
        # the usual sequence: the task loads the row, and the result arrives during the storage calls. The task must
        # not write its old copy of the status: the row stays pending, and counts against MAX_PENDING_UPLOADS.
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
        # the fields of the ingest did not change
        self.assertEqual(upload.status, UploadStatus.UPLOADED)
        self.assertTrue(upload.truncated)
        self.assertIsNotNone(upload.completed_at)

    @patch("zentral.contrib.turbo.tasks.complete_multipart_upload")
    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_a_mismatch_decided_during_the_assembly_stands(self, list_parts, complete):
        # a result that does not agree with its mint arrives during the storage calls. The mismatch stays, and the task
        # writes nothing.
        upload = self._upload(status=UploadStatus.PENDING)
        list_parts.return_value = PARTS

        def the_result_contradicts_its_mint(*args, **kwargs):
            JobUpload.objects.filter(pk=upload.pk).update(
                status=UploadStatus.UPLOADED, verification=UploadVerification.MISMATCH,
                verified_at=timezone.now())
            return {"ETag": '"final"'}

        complete.side_effect = the_result_contradicts_its_mint
        with self.assertLogs("zentral.contrib.turbo.tasks", level="INFO"):
            result = complete_multipart_upload_task(str(upload.pk))
        self.assertFalse(result["recorded"])
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.MISMATCH)

    @patch("zentral.contrib.turbo.tasks.list_multipart_parts")
    def test_a_decided_verdict_is_left_alone(self, list_parts):
        # a decided verification is final
        for verification in (UploadVerification.VERIFIED, UploadVerification.ASSEMBLY_FAILED,
                             UploadVerification.MISMATCH):
            with self.subTest(verification=verification):
                upload = self._upload(verification=verification)
                result = complete_multipart_upload_task(str(upload.pk))
                self.assertEqual(result["status"], "already_decided")
                upload.refresh_from_db()
                self.assertEqual(upload.verification, verification)
        list_parts.assert_not_called()

    def test_a_single_put_is_not_assembled(self):
        upload = self._upload(mode=UploadMode.PUT, upload_id="")
        with self.assertLogs("zentral.contrib.turbo.tasks", level="ERROR"):
            result = complete_multipart_upload_task(str(upload.pk))
        self.assertEqual(result["status"], "not_multipart")
        upload.refresh_from_db()
        self.assertEqual(upload.verification, UploadVerification.PENDING)


@override_settings(STORAGES=S3_STORAGE)
class TurboAbortMultipartTaskTestCase(TurboPublicTestCase):
    """The abort deletes the parts of an upload that will not complete."""

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
        abort.side_effect = MultipartUploadNotFound("NoSuchUpload")
        upload = self._upload()
        self.assertEqual(abort_multipart_upload_task(str(upload.pk))["status"], "aborted")

    @patch("zentral.contrib.turbo.tasks.abort_multipart_upload")
    def test_a_failed_abort_leaves_the_parts_to_the_lifecycle_rule(self, abort):
        # logged, no retry: the bucket rule deletes the parts later
        for error, level in ((StorageUnavailable("SlowDown"), "WARNING"), (StorageError("AccessDenied"), "ERROR")):
            with self.subTest(error=error):
                abort.side_effect = error
                upload = self._upload()
                with self.assertLogs("zentral.contrib.turbo.tasks", level="WARNING") as cm:
                    result = abort_multipart_upload_task(str(upload.pk))
                self.assertEqual([record.levelname for record in cm.records], [level])
                self.assertEqual(result["status"], "not_aborted")
                self.assertEqual(result["error"], str(error))

    @patch("zentral.contrib.turbo.tasks.abort_multipart_upload")
    def test_a_mismatch_drops_the_parts(self, abort):
        # a result that does not agree with its mint: a final verification, so no completion follows
        upload = self._upload(status=UploadStatus.UPLOADED, verification=UploadVerification.MISMATCH)
        self.assertEqual(abort_multipart_upload_task(str(upload.pk))["status"], "aborted")
        abort.assert_called_once()

    @patch("zentral.contrib.turbo.tasks.abort_multipart_upload")
    def test_an_upload_that_is_not_failed_is_left_alone(self, abort):
        # the upload can still complete
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
    """The ingest of a result for a multipart row.

    The completion task verifies a multipart object, so the ingest does not ask the storage. The ingest asks
    for a pending completion, or for the abort of a failed upload.
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
        # the complete call of the agent can be lost, and the result can arrive first
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
        # already decided: no task, and no storage call
        task.apply_async.assert_not_called()
        stat.assert_not_called()

    @patch("zentral.contrib.turbo.public_views.results.abort_multipart_upload_task")
    @patch("zentral.contrib.turbo.public_views.results.complete_multipart_upload_task")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_a_result_that_contradicts_its_mint_is_a_mismatch(self, post_event, task, abort):
        # only the ingest compares the result with the mint. Another file is a mismatch, also after the completion, as
        # on the single-PUT path.
        for verification in (UploadVerification.PENDING, UploadVerification.VERIFIED):
            for echoed in ({"size": 201}, {"sha256": "b" * 64}):
                with self.subTest(verification=verification, echoed=echoed):
                    post_event.reset_mock()
                    abort.reset_mock()
                    token, one_time_job, upload = self._minted(verification=verification)
                    with (self.captureOnCommitCallbacks(execute=True),
                          self.assertLogs("zentral.contrib.turbo.uploads", level="WARNING")):
                        self._report(token, one_time_job, upload,
                                     {"artifact": "archive", "key": upload.key, "size": 200,
                                      "sha256": SHA256, **echoed})
                    upload.refresh_from_db()
                    self.assertEqual(upload.status, UploadStatus.UPLOADED)
                    self.assertEqual(upload.verification, UploadVerification.MISMATCH)
                    self.assertEqual(self._uploads_ref(post_event)["verification"],
                                     UploadVerification.MISMATCH)
                    if verification == UploadVerification.PENDING:
                        # no completion follows, so the parts are deleted now
                        abort.apply_async.assert_called_once_with((str(upload.pk),))
                    else:
                        # already assembled, so no parts to delete
                        abort.apply_async.assert_not_called()
        # decided, so no completion
        task.apply_async.assert_not_called()

    @patch("zentral.contrib.turbo.public_views.results.complete_multipart_upload_task")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_a_failed_assembly_rides_the_event_as_not_verified(self, post_event, task):
        token, one_time_job, upload = self._minted(
            verification=UploadVerification.ASSEMBLY_FAILED)
        with self.captureOnCommitCallbacks(execute=True):
            self._report(token, one_time_job, upload,
                         {"artifact": "archive", "key": upload.key, "size": 200, "sha256": SHA256})
        # the verification, not a boolean: assembly_failed and mismatch are different answers, and a consumer of the
        # event cannot read the database
        self.assertEqual(self._uploads_ref(post_event)["verification"],
                         UploadVerification.ASSEMBLY_FAILED)
        task.apply_async.assert_not_called()

    @patch("zentral.contrib.turbo.public_views.results.abort_multipart_upload_task")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_a_reported_failure_frees_the_parts(self, post_event, task):
        # a bucket rule deletes the parts after some days. The abort deletes them when the result arrives.
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
        # the returned key is not the minted key, so the row fails, and nothing assembles its parts
        token, one_time_job, upload = self._minted()
        with self.captureOnCommitCallbacks(execute=True):
            self._report(token, one_time_job, upload,
                         {"artifact": "archive", "key": "somewhere/else", "size": 200})
        abort.apply_async.assert_called_once_with((str(upload.pk),))
        complete.apply_async.assert_not_called()

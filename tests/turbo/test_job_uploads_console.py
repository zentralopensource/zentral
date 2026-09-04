import uuid
from urllib.parse import parse_qs, urlparse

from django.core.files.base import ContentFile
from django.core.files.storage import storages
from django.test import override_settings
from django.urls import reverse

from zentral.contrib.inventory.models import MachineSnapshotCommit, MetaMachine
from zentral.contrib.turbo.command_backends import CommandBackend
from zentral.contrib.turbo.models import (JobUpload, UploadStatus, UploadVerification,
                                          resolve_upload_schedules)
from zentral.contrib.turbo.pbac import authorize_job_upload_rows

from .utils import (TurboSetupTestCase, force_command, force_configuration, force_enrolled_machine,
                    force_one_time_job, force_recurring_job, turbo_policy)


SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
# staticfiles is carried over: overriding STORAGES replaces the whole dict, and a console page
# renders templates that need it
S3_STORAGE = {"default": {"BACKEND": "storages.backends.s3.S3Storage",
                          "OPTIONS": {"bucket_name": "zentral-tests",
                                      "access_key": "AKIAIOSFODNN7EXAMPLE",
                                      "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                                      "region_name": "us-east-1"}},
              "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"}}

# a deployment with a SEPARATE dist storage: the upload plane writes to `default` throughout, so a
# download reaching for the dist one would point at a bucket the artifact was never written to
SPLIT_STORAGE = {"default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
                 "dist": {"BACKEND": "storages.backends.s3.S3Storage",
                          "OPTIONS": {"bucket_name": "zentral-dist-tests",
                                      "access_key": "AKIAIOSFODNN7EXAMPLE",
                                      "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                                      "region_name": "us-east-1"}},
                 "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"}}

ARTIFACT_ACTIONS = ('Turbo::Action::"viewJobUpload"', 'Turbo::Action::"downloadJobUpload"')


class TurboJobUploadConsoleTestCase(TurboSetupTestCase):
    """The artifacts a machine has been asked for, on its page — and who may fetch one."""

    def _machine_with_upload(self, artifact="archive", status=UploadStatus.UPLOADED,
                             verification=UploadVerification.VERIFIED, recurring=False,
                             backend=CommandBackend.SYSDIAGNOSE, in_mbu=False):
        configuration = force_configuration()
        enrollment, serial_number, _ = force_enrolled_machine(configuration=configuration,
                                                              meta_business_unit=self.mbu)
        if in_mbu:
            # the machine resource carries its meta business units as parents, and they come from the
            # inventory snapshots rather than from the enrollment secret
            MachineSnapshotCommit.objects.commit_machine_snapshot_tree({
                "source": {"module": "zentral.contrib.turbo", "name": "Turbo"},
                "business_unit": enrollment.secret.get_api_enrollment_business_unit().serialize(),
                "serial_number": serial_number,
            })
        command = force_command(backend=backend)
        if recurring:
            schedule = force_recurring_job(configuration=configuration, job=command.job)
        else:
            schedule = force_one_time_job(configuration=configuration, job=command.job,
                                          serial_numbers=[serial_number])
        upload = JobUpload.objects.create(
            schedule_pk=schedule.pk,
            schedule_mode="recurring" if recurring else "one_time",
            serial_number=serial_number, run_id=uuid.uuid4(), artifact=artifact,
            key=f"turbo/uploads/{serial_number}/{schedule.pk}/x/{artifact}_{serial_number}.tar.gz",
            size=1024, sha256=SHA256, status=status, verification=verification,
        )
        return configuration, serial_number, schedule, upload

    def _machine_url(self, serial_number):
        return reverse("turbo:enrolled_machine",
                       args=(MetaMachine(serial_number).get_urlsafe_serial_number(),))

    # the resolver

    def test_resolve_upload_schedules_finds_both_scheduling_models(self):
        # the row holds no foreign key to either, so the schedule is resolved polymorphically — and
        # one lookup yields the configuration and the job, which is what a decision needs
        configuration, _, one_time_job, one_time_upload = self._machine_with_upload()
        _, _, recurring_job, recurring_upload = self._machine_with_upload(recurring=True)
        resolved = resolve_upload_schedules([one_time_upload, recurring_upload])
        self.assertEqual(resolved[one_time_job.pk], (configuration, one_time_job.job))
        self.assertEqual(resolved[recurring_upload.schedule_pk][1], recurring_job.job)

    def test_resolve_upload_schedules_no_uploads(self):
        self.assertEqual(resolve_upload_schedules([]), {})

    def test_an_upload_whose_schedule_is_gone_is_dropped(self):
        # the row survives a deleted schedule — the artifact is still in the bucket — but there is no
        # configuration to name and no job to read, so there is nothing to decide against
        _, _, one_time_job, upload = self._machine_with_upload()
        one_time_job.delete()
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine",
                                     actions=ARTIFACT_ACTIONS))
        with self.assertLogs("zentral.contrib.turbo.pbac", level="WARNING"):
            self.assertEqual(authorize_job_upload_rows(self.user, [upload]), [])

    # the machine page

    def test_the_page_lists_the_artifacts(self):
        _, serial_number, _, upload = self._machine_with_upload()
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine",
                                            actions=ARTIFACT_ACTIONS))
        response = self.client.get(self._machine_url(serial_number))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Collected artifacts (1)")
        self.assertContains(response, "archive")
        self.assertContains(response, reverse("turbo:download_job_upload", args=(upload.pk,)))

    def test_without_the_view_action_the_artifact_is_absent(self):
        # filtered rather than merely unlinked: an upload the user may not see is not on the page at
        # all, so its existence, its name and its size do not leak
        _, serial_number, _, upload = self._machine_with_upload()
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine", actions=()))
        response = self.client.get(self._machine_url(serial_number))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Collected artifacts (0)")
        self.assertNotContains(response, reverse("turbo:download_job_upload", args=(upload.pk,)))

    def test_view_without_download_shows_the_row_and_no_link(self):
        # the distinction the two actions exist for
        _, serial_number, _, upload = self._machine_with_upload()
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine",
                                     actions=('Turbo::Action::"viewJobUpload"',)))
        response = self.client.get(self._machine_url(serial_number))
        self.assertContains(response, "Collected artifacts (1)")
        self.assertNotContains(response, reverse("turbo:download_job_upload", args=(upload.pk,)))

    def test_a_pending_upload_offers_no_download(self):
        _, serial_number, _, upload = self._machine_with_upload(
            status=UploadStatus.PENDING, verification=UploadVerification.PENDING)
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine",
                                     actions=ARTIFACT_ACTIONS))
        response = self.client.get(self._machine_url(serial_number))
        self.assertContains(response, "Collected artifacts (1)")
        self.assertNotContains(response, reverse("turbo:download_job_upload", args=(upload.pk,)))

    def test_the_kind_filter_covers_the_artifacts(self):
        _, serial_number, _, _ = self._machine_with_upload()
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine",
                                     actions=ARTIFACT_ACTIONS))
        response = self.client.get(self._machine_url(serial_number), {"kind": "sysdiagnose"})
        self.assertContains(response, "Collected artifacts (1)")
        response = self.client.get(self._machine_url(serial_number), {"kind": "script"})
        self.assertContains(response, "Collected artifacts (0)")

    # policy shapes the design promises

    def test_a_configuration_forbid_covers_the_artifacts_too(self):
        # the reason for the second parent. With only the machine parent this policy would silently
        # cover the scheduling and miss the artifacts.
        configuration, serial_number, _, upload = self._machine_with_upload()
        self.login_with_policy(
            turbo_policy(self.group, "turbo.view_enrolledmachine", actions=ARTIFACT_ACTIONS)
            + f'forbid (principal, action in [{", ".join(ARTIFACT_ACTIONS)}], '
              f'resource in Turbo::Configuration::"{configuration.pk}");\n'
        )
        response = self.client.get(self._machine_url(serial_number))
        self.assertContains(response, "Collected artifacts (0)")
        self.assertEqual(
            self.client.get(reverse("turbo:download_job_upload", args=(upload.pk,))).status_code,
            403)

    def test_an_mbu_forbid_reaches_three_levels_up(self):
        # JobUpload -> Inventory::Machine -> Inventory::MetaBusinessUnit
        _, serial_number, _, upload = self._machine_with_upload(in_mbu=True)
        self.login_with_policy(
            turbo_policy(self.group, "turbo.view_enrolledmachine", actions=ARTIFACT_ACTIONS)
            + f'forbid (principal, action in [{", ".join(ARTIFACT_ACTIONS)}], '
              f'resource in Inventory::MetaBusinessUnit::"{self.mbu.pk}");\n'
        )
        self.assertContains(self.client.get(self._machine_url(serial_number)),
                            "Collected artifacts (0)")
        self.assertEqual(
            self.client.get(reverse("turbo:download_job_upload", args=(upload.pk,))).status_code,
            403)

    def test_a_machine_with_no_snapshot_has_no_mbu_to_scope_on(self):
        # worth pinning: the MBU parents come from the inventory snapshots, so a machine that has
        # only ever enrolled is in no meta business unit as far as a policy is concerned. Defence in
        # depth, not a boundary — which is exactly why the configuration parent exists.
        _, serial_number, _, _ = self._machine_with_upload()
        self.login_with_policy(
            turbo_policy(self.group, "turbo.view_enrolledmachine", actions=ARTIFACT_ACTIONS)
            + f'forbid (principal, action in [{", ".join(ARTIFACT_ACTIONS)}], '
              f'resource in Inventory::MetaBusinessUnit::"{self.mbu.pk}");\n'
        )
        self.assertContains(self.client.get(self._machine_url(serial_number)),
                            "Collected artifacts (1)")

    def test_a_policy_can_read_the_artifact_name_and_the_job_kind(self):
        _, serial_number, _, _ = self._machine_with_upload(artifact="manifest",
                                                           backend=CommandBackend.FILE_EXPORT)
        self.login_with_policy(
            turbo_policy(self.group, "turbo.view_enrolledmachine", actions=ARTIFACT_ACTIONS)
            + f'forbid (principal, action in [{", ".join(ARTIFACT_ACTIONS)}], resource) '
              'when { resource.job.kind == "file_export" && resource.artifact == "manifest" };\n'
        )
        self.assertContains(self.client.get(self._machine_url(serial_number)),
                            "Collected artifacts (0)")

    # the download

    def test_the_download_serves_the_file(self):
        _, _, _, upload = self._machine_with_upload()
        storage = storages["default"]
        storage.save(upload.key, ContentFile(b"a sysdiagnose"))
        self.addCleanup(storage.delete, upload.key)
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine",
                                     actions=ARTIFACT_ACTIONS))
        response = self.client.get(reverse("turbo:download_job_upload", args=(upload.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(b"".join(response.streaming_content), b"a sysdiagnose")
        # saved, not rendered, and under the name the key already ends in
        self.assertIn("attachment", response["Content-Disposition"])
        self.assertIn(upload.key.rsplit("/", 1)[-1], response["Content-Disposition"])

    @override_settings(STORAGES=SPLIT_STORAGE)
    def test_the_download_reads_the_storage_the_plane_writes_to(self):
        # the whole plane writes to `default`: the mint presigns against it, the hosted PUT saves to
        # it, the verification reads it. A deployment with a separate dist storage would otherwise
        # send every download to a bucket that never held the artifact, and answer a 404 after the
        # redirect.
        _, _, _, upload = self._machine_with_upload()
        storage = storages["default"]
        storage.save(upload.key, ContentFile(b"a sysdiagnose"))
        self.addCleanup(storage.delete, upload.key)
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine",
                                            actions=ARTIFACT_ACTIONS))
        response = self.client.get(reverse("turbo:download_job_upload", args=(upload.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(b"".join(response.streaming_content), b"a sysdiagnose")

    @override_settings(STORAGES=S3_STORAGE)
    def test_a_signing_storage_redirects_with_the_disposition_signed(self):
        # the key already ends in the filename, so a browser saves the right name from the path — but
        # a small manifest.json would render in the tab instead, and the disposition settles it
        _, _, _, upload = self._machine_with_upload(artifact="manifest")
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine",
                                     actions=ARTIFACT_ACTIONS))
        response = self.client.get(reverse("turbo:download_job_upload", args=(upload.pk,)))
        self.assertEqual(response.status_code, 302)
        query = parse_qs(urlparse(response["Location"]).query)
        self.assertIn("attachment", query["response-content-disposition"][0])

    def test_the_download_without_the_action_is_refused(self):
        _, _, _, upload = self._machine_with_upload()
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine",
                                     actions=('Turbo::Action::"viewJobUpload"',)))
        self.assertEqual(
            self.client.get(reverse("turbo:download_job_upload", args=(upload.pk,))).status_code,
            403)

    def test_the_download_needs_the_machine_page_permission_too(self):
        # defence in depth: a 404 for an unknown machine and a 403 for one you cannot reach must not
        # be distinguishable to someone who cannot list enrolled machines at all
        _, _, _, upload = self._machine_with_upload()
        self.login_with_policy(turbo_policy(self.group, actions=ARTIFACT_ACTIONS))
        self.assertEqual(
            self.client.get(reverse("turbo:download_job_upload", args=(upload.pk,))).status_code,
            403)

    def test_an_upload_that_never_landed_is_not_downloadable(self):
        _, _, _, upload = self._machine_with_upload(status=UploadStatus.FAILED,
                                                    verification=UploadVerification.PENDING)
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine",
                                     actions=ARTIFACT_ACTIONS))
        self.assertEqual(
            self.client.get(reverse("turbo:download_job_upload", args=(upload.pk,))).status_code,
            404)

    def test_an_object_the_expiry_rule_removed(self):
        # expected, not exceptional: the rule deletes objects out from under rows that outlive them
        _, _, _, upload = self._machine_with_upload()
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine",
                                     actions=ARTIFACT_ACTIONS))
        self.assertEqual(
            self.client.get(reverse("turbo:download_job_upload", args=(upload.pk,))).status_code,
            404)

    def test_the_download_of_an_upload_whose_schedule_is_gone(self):
        _, _, one_time_job, upload = self._machine_with_upload()
        one_time_job.delete()
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine",
                                     actions=ARTIFACT_ACTIONS))
        self.assertEqual(
            self.client.get(reverse("turbo:download_job_upload", args=(upload.pk,))).status_code,
            404)

    def test_an_unknown_upload(self):
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine",
                                     actions=ARTIFACT_ACTIONS))
        self.assertEqual(
            self.client.get(reverse("turbo:download_job_upload", args=(uuid.uuid4(),))).status_code,
            404)

    def test_the_download_requires_a_login(self):
        _, _, _, upload = self._machine_with_upload()
        response = self.client.get(reverse("turbo:download_job_upload", args=(upload.pk,)))
        self.assertRedirects(response,
                             "{}?next={}".format(reverse("login"),
                                                 reverse("turbo:download_job_upload",
                                                         args=(upload.pk,))))

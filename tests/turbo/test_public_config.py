import json
from datetime import timedelta
from unittest.mock import patch
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MachineTag, Tag
from zentral.contrib.turbo.events import TurboRequestEvent
from zentral.contrib.turbo.models import EnrolledMachine, MachineJobStatus
from .utils import (TurboPublicTestCase, force_configuration, force_enrolled_machine,
                    force_mscp_check, force_one_time_job, force_recurring_job, force_script)


class TurboConfigPublicTestCase(TurboPublicTestCase):
    def _config(self, token):
        return self.client.get(reverse("turbo_public:config"),
                               HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}")

    # auth

    def test_config_unauthenticated(self):
        self.assertEqual(self.client.get(reverse("turbo_public:config")).status_code, 401)

    def test_config_bad_token(self):
        self.assertEqual(self._config("not-a-real-token").status_code, 401)

    def test_config_empty(self):
        configuration = force_configuration()
        _, _, token = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        response = self._config(token)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["config_refresh_interval"], configuration.config_refresh_interval)
        self.assertEqual(data["results_batch_size"], configuration.results_batch_size)
        self.assertEqual(data["collect_inventory"], configuration.collect_inventory)
        self.assertEqual(data["inventory_interval"], configuration.inventory_interval)
        self.assertEqual(data["jobs"], [])

    def test_config_stamps_last_seen(self):
        configuration = force_configuration()
        enrollment, serial_number, token = force_enrolled_machine(
            configuration=configuration, meta_business_unit=self.mbu)
        em = EnrolledMachine.objects.get(enrollment=enrollment, serial_number=serial_number)
        self.assertIsNone(em.last_seen_at)
        self.assertEqual(self._config(token).status_code, 200)
        em.refresh_from_db()
        self.assertIsNotNone(em.last_seen_at)
        # within the throttle window a second request does not re-stamp
        first = em.last_seen_at
        self.assertEqual(self._config(token).status_code, 200)
        em.refresh_from_db()
        self.assertEqual(em.last_seen_at, first)

    # recurring

    def test_config_scheduled_script(self):
        configuration = force_configuration()
        _, _, token = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        script = force_script(compliance_check=True)
        recurring_job = force_recurring_job(configuration=configuration, job=script.job, interval=3600)
        jobs = self._config(token).json()["jobs"]
        self.assertEqual(len(jobs), 1)
        job = jobs[0]
        self.assertEqual(job["kind"], "script")
        self.assertEqual(job["pk"], str(script.job.pk))
        self.assertEqual(job["version"], script.job.version)
        self.assertEqual(job["schedule"], {"mode": "recurring", "pk": str(recurring_job.pk), "interval": 3600})
        self.assertEqual(job["payload"], {"source": script.source, "compliance": True,
                                          "arch_amd64": True, "arch_arm64": True,
                                          "min_os_version": "", "max_os_version": ""})

    def test_config_scheduled_interval_defaults_to_configuration(self):
        configuration = force_configuration()
        _, _, token = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        force_recurring_job(configuration=configuration, interval=None)
        jobs = self._config(token).json()["jobs"]
        self.assertEqual(jobs[0]["schedule"]["interval"], configuration.default_check_interval)

    def test_config_mscp_payload_odv(self):
        configuration = force_configuration()
        _, _, token = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        mscp_check = force_mscp_check(odv_int=15)
        force_recurring_job(configuration=configuration, job=mscp_check.job)
        jobs = self._config(token).json()["jobs"]
        self.assertEqual(jobs[0]["kind"], "mscp_check")
        self.assertEqual(jobs[0]["payload"], {"rule_id": mscp_check.rule_id, "odv_int": 15})

    def test_config_mscp_payload_baseline(self):
        configuration = force_configuration()
        _, _, token = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        mscp_check = force_mscp_check(baseline="cis_lvl1")
        force_recurring_job(configuration=configuration, job=mscp_check.job)
        jobs = self._config(token).json()["jobs"]
        self.assertEqual(jobs[0]["kind"], "mscp_check")
        self.assertEqual(jobs[0]["payload"], {"rule_id": mscp_check.rule_id, "baseline": "cis_lvl1"})

    # scope

    def test_config_scope_by_tag(self):
        configuration = force_configuration()
        _, serial_number, token = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        tag = Tag.objects.create(name=get_random_string(12))
        MachineTag.objects.create(serial_number=serial_number, tag=tag)
        force_recurring_job(configuration=configuration, tags=[tag])
        force_recurring_job(configuration=configuration, tags=[Tag.objects.create(name=get_random_string(12))])
        self.assertEqual(len(self._config(token).json()["jobs"]), 1)

    def test_config_scope_by_serial(self):
        configuration = force_configuration()
        _, serial_number, token = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        force_recurring_job(configuration=configuration, serial_numbers=[serial_number])
        self.assertEqual(len(self._config(token).json()["jobs"]), 1)

    def test_config_excluded_by_tag(self):
        configuration = force_configuration()
        _, serial_number, token = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        tag = Tag.objects.create(name=get_random_string(12))
        MachineTag.objects.create(serial_number=serial_number, tag=tag)
        recurring_job = force_recurring_job(configuration=configuration)  # config-wide
        recurring_job.excluded_tags.set([tag])
        self.assertEqual(self._config(token).json()["jobs"], [])

    def test_config_excluded_by_serial(self):
        configuration = force_configuration()
        _, serial_number, token = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        recurring_job = force_recurring_job(configuration=configuration)  # config-wide
        recurring_job.excluded_serial_numbers = [serial_number]
        recurring_job.save()
        self.assertEqual(self._config(token).json()["jobs"], [])

    def test_config_other_configuration_not_served(self):
        configuration = force_configuration()
        _, _, token = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        force_recurring_job()  # different configuration
        self.assertEqual(self._config(token).json()["jobs"], [])

    # one-time

    def test_config_one_time_job(self):
        configuration = force_configuration()
        _, _, token = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        one_time_job = force_one_time_job(configuration=configuration)
        jobs = self._config(token).json()["jobs"]
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["schedule"], {"mode": "one_time", "pk": str(one_time_job.pk)})
        # nothing is minted at config time
        self.assertEqual(MachineJobStatus.objects.count(), 0)

    def test_config_one_time_job_future_not_before(self):
        configuration = force_configuration()
        _, _, token = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        force_one_time_job(configuration=configuration, not_before=timezone.now() + timedelta(days=1))
        self.assertEqual(self._config(token).json()["jobs"], [])

    def test_config_one_time_job_not_served_after_result(self):
        configuration = force_configuration()
        _, serial_number, token = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        one_time_job = force_one_time_job(configuration=configuration)
        self.assertEqual(len(self._config(token).json()["jobs"]), 1)
        MachineJobStatus.objects.create(
            serial_number=serial_number, job=one_time_job.job, one_time_job=one_time_job,
            last_result_at=timezone.now())
        self.assertEqual(self._config(token).json()["jobs"], [])

    def test_config_one_time_job_stale_version_result_does_not_close_it(self):
        # a result for an old definition version must not close the one-time job: the bumped version
        # still needs to run, so the config keeps serving it
        configuration = force_configuration()
        _, serial_number, token = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        one_time_job = force_one_time_job(configuration=configuration)
        served = self._config(token).json()["jobs"]
        self.assertEqual(len(served), 1)
        stale_version = one_time_job.job.version - 1 if one_time_job.job.version > 1 else 0
        result = {
            "kind": one_time_job.job.kind, "pk": str(one_time_job.job.pk), "version": stale_version,
            "run": {"at": "2026-06-22T10:00:00Z", "duration": 0.2, "schedule_pk": served[0]["schedule"]["pk"]},
            "result": {"exit_code": 0},
        }
        self.client.post(reverse("turbo_public:results"), data=json.dumps({"results": [result]}),
                         content_type="application/json",
                         HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}")
        machine_job_status = MachineJobStatus.objects.get(serial_number=serial_number, one_time_job=one_time_job)
        self.assertIsNone(machine_job_status.last_result_at)
        # still served, since no current-version result has closed it
        self.assertEqual(len(self._config(token).json()["jobs"]), 1)

    def test_one_time_cycle_works_without_status(self):
        # status is optional: config → results → config gates the one-time job with no status report
        configuration = force_configuration()
        _, serial_number, token = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        one_time_job = force_one_time_job(configuration=configuration)
        served = self._config(token).json()["jobs"]
        self.assertEqual(len(served), 1)
        result = {
            "kind": one_time_job.job.kind, "pk": str(one_time_job.job.pk),
            "version": one_time_job.job.version,
            "run": {"at": "2026-06-22T10:00:00Z", "duration": 0.2,
                    "schedule_pk": served[0]["schedule"]["pk"]},
            "result": {"exit_code": 0},
        }
        self.client.post(reverse("turbo_public:results"), data=json.dumps({"results": [result]}),
                         content_type="application/json",
                         HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}")
        # gated by the result alone — and no status was ever sent (seen fields untouched)
        self.assertEqual(self._config(token).json()["jobs"], [])
        machine_job_status = MachineJobStatus.objects.get(serial_number=serial_number, one_time_job=one_time_job)
        self.assertIsNone(machine_job_status.last_seen_at)

    # event

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_config_event(self, post_event):
        configuration = force_configuration()
        enrollment, serial_number, token = force_enrolled_machine(
            configuration=configuration, meta_business_unit=self.mbu)
        force_recurring_job(configuration=configuration, job=force_script().job)
        with self.captureOnCommitCallbacks(execute=True):
            self._config(token)
        events = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], TurboRequestEvent)]
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.metadata.machine_serial_number, serial_number)
        self.assertEqual(event.payload["request_type"], "config")
        self.assertEqual(event.payload["enrollment"]["pk"], enrollment.pk)
        self.assertEqual(event.payload["configuration"]["pk"], configuration.pk)
        # the config request event is a marker — the served jobs are not listed on it
        self.assertNotIn("jobs", event.payload)
        metadata = event.metadata.serialize()
        # only the enrollment + configuration are linked (no per-job links on the request marker)
        self.assertEqual(metadata["objects"], {
            "turbo_enrollment": [str(enrollment.pk)],
            "turbo_configuration": [str(configuration.pk)],
        })
        # the request is built from the request, so it carries method / view (not just UA + IP)
        self.assertEqual(metadata["request"]["method"], "GET")
        self.assertEqual(metadata["request"]["view"], "turbo_public:config")

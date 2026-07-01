from datetime import timedelta
from django.test import TestCase
from django.utils import timezone
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import Tag
from zentral.contrib.turbo.api_views.enrollments import EnrollmentConfiguration
from zentral.contrib.turbo.compliance_checks import TurboMSCPCheck, TurboScript
from zentral.contrib.turbo.events import TurboRequestEvent, TurboResultEvent
from zentral.contrib.turbo.models import Configuration, MachineJobStatus, RecurringJob, Script
from zentral.core.compliance_checks.models import ComplianceCheck
from zentral.core.events.base import EventMetadata
from .utils import (force_configuration, force_enrollment, force_mscp_check,
                    force_one_time_job, force_recurring_job, force_script, make_enrolled_machine)


class TurboModelStrTestCase(TestCase):
    def test_job_str(self):
        job = force_script().job
        self.assertEqual(str(job), f"Script job {job.pk}")

    def test_collect_inventory_help_text_not_a_job(self):
        # inventory is not a scheduled job in v1; the help text must not describe it as one
        help_text = Configuration._meta.get_field("collect_inventory").help_text
        self.assertNotIn("job", help_text.lower())

    def test_enrolled_machine_str(self):
        em = make_enrolled_machine(force_enrollment())
        self.assertEqual(str(em), em.serial_number)

    def test_recurring_job_str(self):
        rj = force_recurring_job()
        self.assertEqual(str(rj), f"{rj.job} in {rj.configuration}")

    def test_one_time_job_str(self):
        otj = force_one_time_job()
        self.assertEqual(str(otj), f"one-time {otj.job}")

    def test_machine_job_status_str(self):
        rj = force_recurring_job()
        mjs = MachineJobStatus.objects.create(serial_number="C02X", job=rj.job)
        self.assertEqual(str(mjs), f"{rj.job} on C02X")

    def test_enrollment_description_for_distributor(self):
        enrollment = force_enrollment()
        self.assertEqual(enrollment.get_description_for_distributor(),
                         f"Turbo configuration: {enrollment.configuration}")


class TurboConfigurationSaveTestCase(TestCase):
    def test_save_does_not_bump_enrollment(self):
        # editing a configuration must NOT bump its enrollments: the MDM profile is config-independent
        # (only BaseURL + secret), and operational settings reach the agent via /config/. A re-enrollment
        # is triggered manually through the bump action instead.
        cfg = force_configuration()
        enrollment = force_enrollment(configuration=cfg)
        version = enrollment.version
        cfg.description = "updated"
        cfg.save()
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.version, version)


class TurboSerializeForEventTestCase(TestCase):
    def test_enrollment_serialize_for_event_keys_only(self):
        # the heartbeat events use the compact keys_only form
        enrollment = force_enrollment()
        self.assertEqual(enrollment.serialize_for_event(keys_only=True), {"pk": enrollment.pk})

    def test_script_optional_fields(self):
        script = Script.objects.create(name=get_random_string(12), source="exit 0",
                                       description="check it", min_os_version="13.0", max_os_version="14.0")
        d = script.serialize_for_event()
        self.assertEqual(d["description"], "check it")
        self.assertEqual(d["min_os_version"], "13.0")
        self.assertEqual(d["max_os_version"], "14.0")

    def test_mscp_check_wire_payload_and_event_odv_string(self):
        mscp = force_mscp_check(odv_string="strict")
        self.assertEqual(mscp.wire_payload()["odv_string"], "strict")
        self.assertEqual(mscp.serialize_for_event()["odv_string"], "strict")

    def test_mscp_check_wire_payload_and_event_odv_bool(self):
        mscp = force_mscp_check(odv_bool=True)
        self.assertEqual(mscp.wire_payload()["odv_bool"], True)
        self.assertEqual(mscp.serialize_for_event()["odv_bool"], True)

    def test_mscp_check_event_baseline(self):
        mscp = force_mscp_check(baseline="cis_lvl1")
        self.assertEqual(mscp.serialize_for_event()["baseline"], "cis_lvl1")

    def test_job_scope_serialize(self):
        cfg = force_configuration()
        tag, excluded = Tag.objects.create(name=get_random_string(12)), Tag.objects.create(name=get_random_string(12))
        rj = RecurringJob.objects.create(configuration=cfg, job=force_script().job,
                                         serial_numbers=["S1"], excluded_serial_numbers=["S2"])
        rj.tags.set([tag])
        rj.excluded_tags.set([excluded])
        d = rj.serialize_for_event()
        self.assertEqual([t["pk"] for t in d["tags"]], [tag.pk])
        self.assertEqual([t["pk"] for t in d["excluded_tags"]], [excluded.pk])
        self.assertEqual(d["serial_numbers"], ["S1"])
        self.assertEqual(d["excluded_serial_numbers"], ["S2"])

    def test_one_time_job_serialize_not_after(self):
        not_after = timezone.now() + timedelta(days=1)
        otj = force_one_time_job(not_after=not_after)
        self.assertEqual(otj.serialize_for_event()["not_after"], not_after.isoformat())


class TurboComplianceCheckClassTestCase(TestCase):
    def test_turbo_script_redirect_and_property(self):
        script = force_script(compliance_check=True)
        cc = TurboScript(script.compliance_check)
        self.assertEqual(cc.script, script)
        self.assertEqual(cc.get_redirect_url(), script.get_absolute_url())

    def test_turbo_script_orphan_compliance_check(self):
        orphan = ComplianceCheck.objects.create(model=TurboScript.get_model(),
                                                name=get_random_string(12), version=1)
        self.assertIsNone(TurboScript(orphan).script)

    def test_turbo_mscp_check_redirect_and_property(self):
        mscp = force_mscp_check()
        cc = TurboMSCPCheck(mscp.compliance_check)
        self.assertEqual(cc.mscp_check, mscp)
        self.assertEqual(cc.get_redirect_url(), mscp.get_absolute_url())

    def test_turbo_mscp_check_orphan_compliance_check(self):
        orphan = ComplianceCheck.objects.create(model=TurboMSCPCheck.get_model(),
                                                name=get_random_string(12), version=1)
        self.assertIsNone(TurboMSCPCheck(orphan).mscp_check)


class TurboEventLinkedObjectsTestCase(TestCase):
    def test_ref_without_pk_skipped(self):
        # a ref carrying no pk / schedule yields no job or schedule link
        event = TurboRequestEvent(EventMetadata(), {"jobs": [{"kind": "script"}]})
        self.assertEqual(event.get_linked_objects_keys(), {})

    def test_links_job_and_schedule_deduped(self):
        # a job linked from its pk, the schedule from schedule.mode + pk, deduped across refs
        event = TurboRequestEvent(EventMetadata(), {"jobs": [
            {"kind": "script", "pk": "job-1", "schedule": {"mode": "recurring", "pk": "rj-1"}},
            {"kind": "script", "pk": "job-1", "schedule": {"mode": "recurring", "pk": "rj-1"}},
            {"kind": "mscp_check", "pk": "job-2", "schedule": {"mode": "one_time", "pk": "otj-1"}},
        ]})
        self.assertEqual(event.get_linked_objects_keys(), {
            "turbo_job": [("job-1",), ("job-2",)],
            "turbo_recurring_job": [("rj-1",)],
            "turbo_one_time_job": [("otj-1",)],
        })

    def test_result_event_links_schedule_from_run(self):
        # a result event carries the schedule kind on run.mode (+ run.schedule_pk) at the payload top level
        event = TurboResultEvent(EventMetadata(), {
            "kind": "script", "pk": "job-1",
            "run": {"schedule_pk": "rj-1", "mode": "recurring"}, "result": {"exit_code": 0}})
        self.assertEqual(event.get_linked_objects_keys(), {
            "turbo_job": [("job-1",)],
            "turbo_recurring_job": [("rj-1",)],
        })


class TurboEnrollmentConfigurationBaseTestCase(TestCase):
    def test_get_content_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            EnrollmentConfiguration().get_content(None)

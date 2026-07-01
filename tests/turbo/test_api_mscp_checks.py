from unittest.mock import patch
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.turbo.models import Job, MSCPCheck
from zentral.core.compliance_checks.models import ComplianceCheck
from .utils import TurboAPITestCase, force_mscp_check, force_recurring_job


class TurboMSCPCheckAPITestCase(TurboAPITestCase):
    def test_create_mscp_check_unauthorized(self):
        response = self.post(reverse("turbo_api:mscp_checks"),
                             {"rule_id": get_random_string(12)}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_mscp_check_permission_denied(self):
        response = self.post(reverse("turbo_api:mscp_checks"), {"rule_id": get_random_string(12)})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_mscp_check(self, post_event):
        self.set_permissions("turbo.add_mscpcheck")
        rule_id = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True):
            response = self.post(reverse("turbo_api:mscp_checks"),
                                 {"rule_id": rule_id, "odv_int": 15})
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertEqual(data["version"], 1)
        mscp_check = MSCPCheck.objects.get(pk=data["id"])
        self.assertEqual(mscp_check.rule_id, rule_id)
        self.assertEqual(mscp_check.baseline, "")
        self.assertEqual(mscp_check.odv_int, 15)
        self.assertEqual(mscp_check.job.kind, "mscp_check")
        self.assertEqual(mscp_check.job.version, 1)
        self.assertEqual(mscp_check.compliance_check.model, "TurboMSCPCheck")
        self.assertEqual(mscp_check.compliance_check.name, f"{rule_id} = 15")
        self.assertEqual(data["compliance_check_id"], mscp_check.compliance_check.pk)
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        self.assertEqual(audit_events[0].payload["action"], "created")
        self.assertEqual(audit_events[0].payload["object"]["model"], "turbo.mscpcheck")
        metadata = audit_events[0].metadata.serialize()
        self.assertEqual(metadata["objects"], {"turbo_mscp_check": [str(mscp_check.pk)]})

    def test_create_mscp_check_baseline(self):
        self.set_permissions("turbo.add_mscpcheck")
        rule_id = get_random_string(12)
        response = self.post(reverse("turbo_api:mscp_checks"),
                             {"rule_id": rule_id, "baseline": "cis_lvl1"})
        self.assertEqual(response.status_code, 201)
        mscp_check = MSCPCheck.objects.get(pk=response.json()["id"])
        self.assertEqual(mscp_check.baseline, "cis_lvl1")
        self.assertIsNone(mscp_check.odv)
        self.assertEqual(mscp_check.compliance_check.name, f"{rule_id} / cis_lvl1")

    def test_create_mscp_check_too_many_odv(self):
        self.set_permissions("turbo.add_mscpcheck")
        response = self.post(reverse("turbo_api:mscp_checks"),
                             {"rule_id": get_random_string(12), "odv_int": 1, "odv_string": "x"})
        self.assertEqual(response.status_code, 400)

    def test_create_mscp_check_baseline_and_odv_rejected(self):
        self.set_permissions("turbo.add_mscpcheck")
        response = self.post(reverse("turbo_api:mscp_checks"),
                             {"rule_id": get_random_string(12), "baseline": "cis_lvl1", "odv_int": 15})
        self.assertEqual(response.status_code, 400)

    def test_create_mscp_check_empty_odv_string_is_no_override(self):
        self.set_permissions("turbo.add_mscpcheck")
        rule_id = get_random_string(12)
        response = self.post(reverse("turbo_api:mscp_checks"),
                             {"rule_id": rule_id, "odv_string": ""})
        self.assertEqual(response.status_code, 201)
        mscp_check = MSCPCheck.objects.get(pk=response.json()["id"])
        self.assertIsNone(mscp_check.odv_string)
        self.assertEqual(mscp_check.compliance_check.name, rule_id)

    def test_list_mscp_checks(self):
        mscp_check = force_mscp_check()
        self.set_permissions("turbo.view_mscpcheck")
        response = self.get(reverse("turbo_api:mscp_checks"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["results"][0]["id"], str(mscp_check.pk))

    def test_get_mscp_check(self):
        mscp_check = force_mscp_check(odv_int=10)
        self.set_permissions("turbo.view_mscpcheck")
        response = self.get(reverse("turbo_api:mscp_check", args=(mscp_check.pk,)))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["rule_id"], mscp_check.rule_id)
        self.assertEqual(data["odv_int"], 10)
        self.assertEqual(data["version"], 1)
        self.assertEqual(data["compliance_check_id"], mscp_check.compliance_check.pk)

    def test_update_mscp_check_bumps_version(self):
        mscp_check = force_mscp_check(odv_int=10)
        cc_pk = mscp_check.compliance_check.pk
        self.set_permissions("turbo.change_mscpcheck")
        response = self.put(reverse("turbo_api:mscp_check", args=(mscp_check.pk,)),
                            {"rule_id": mscp_check.rule_id, "odv_int": 20})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["version"], 2)
        mscp_check = MSCPCheck.objects.get(pk=mscp_check.pk)
        self.assertEqual(mscp_check.odv_int, 20)
        self.assertEqual(mscp_check.job.version, 2)
        self.assertEqual(mscp_check.compliance_check.pk, cc_pk)
        self.assertEqual(mscp_check.compliance_check.version, 2)
        self.assertEqual(mscp_check.compliance_check.name, f"{mscp_check.rule_id} = 20")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_mscp_check(self, post_event):
        mscp_check = force_mscp_check()
        pk, job_pk, cc_pk = mscp_check.pk, mscp_check.job.pk, mscp_check.compliance_check.pk
        self.set_permissions("turbo.delete_mscpcheck")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.delete(reverse("turbo_api:mscp_check", args=(pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertFalse(MSCPCheck.objects.filter(pk=pk).exists())
        self.assertFalse(Job.objects.filter(pk=job_pk).exists())
        self.assertFalse(ComplianceCheck.objects.filter(pk=cc_pk).exists())
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        self.assertEqual(audit_events[0].payload["action"], "deleted")

    def test_delete_scheduled_mscp_check_blocked(self):
        mscp_check = force_mscp_check()
        force_recurring_job(job=mscp_check.job)
        self.set_permissions("turbo.delete_mscpcheck")
        response = self.delete(reverse("turbo_api:mscp_check", args=(mscp_check.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertTrue(MSCPCheck.objects.filter(pk=mscp_check.pk).exists())

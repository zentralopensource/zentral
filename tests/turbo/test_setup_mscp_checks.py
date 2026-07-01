from unittest.mock import patch
from django.db import IntegrityError, transaction
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.turbo.models import Job, MSCPCheck
from zentral.core.compliance_checks.models import ComplianceCheck
from .utils import TurboSetupTestCase, force_configuration, force_mscp_check, force_recurring_job


class TurboSetupMSCPChecksTestCase(TurboSetupTestCase):
    # mSCP checks

    def test_mscp_checks_redirect(self):
        self.login_redirect("mscp_checks")

    def test_mscp_checks_permission_denied(self):
        self.login()
        response = self.client.get(reverse("turbo:mscp_checks"))
        self.assertEqual(response.status_code, 403)

    def test_mscp_checks(self):
        force_mscp_check()
        self.login("turbo.view_mscpcheck")
        response = self.client.get(reverse("turbo:mscp_checks"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/mscpcheck_list.html")

    def test_mscp_checks_search_by_rule(self):
        mscp_check = force_mscp_check()
        force_mscp_check()
        self.login("turbo.view_mscpcheck")
        response = self.client.get(reverse("turbo:mscp_checks"), {"q": mscp_check.rule_id})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["object_list"]), [mscp_check])

    def test_mscp_checks_search_by_configuration(self):
        configuration = force_configuration()
        scheduled = force_mscp_check()
        force_recurring_job(configuration=configuration, job=scheduled.job)
        force_mscp_check()  # not scheduled anywhere
        self.login("turbo.view_mscpcheck")
        response = self.client.get(reverse("turbo:mscp_checks"), {"configuration": configuration.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["object_list"]), [scheduled])

    def test_mscp_checks_search_no_result_shows_empty_results(self):
        force_mscp_check()
        self.login("turbo.view_mscpcheck")
        response = self.client.get(reverse("turbo:mscp_checks"), {"q": get_random_string(20)})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["object_list"]), [])
        self.assertContains(response, "We didn't find any item")

    def test_mscp_check_list_delete_button_shown_when_not_scheduled(self):
        mscp_check = force_mscp_check()
        self.login("turbo.view_mscpcheck", "turbo.delete_mscpcheck")
        response = self.client.get(reverse("turbo:mscp_checks"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("turbo:delete_mscp_check", args=(mscp_check.pk,)))

    def test_mscp_check_list_delete_button_hidden_when_scheduled(self):
        mscp_check = force_mscp_check()
        force_recurring_job(job=mscp_check.job)
        self.login("turbo.view_mscpcheck", "turbo.delete_mscpcheck")
        response = self.client.get(reverse("turbo:mscp_checks"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, reverse("turbo:delete_mscp_check", args=(mscp_check.pk,)))

    def test_mscp_check_list_delete_button_hidden_without_perm(self):
        mscp_check = force_mscp_check()
        self.login("turbo.view_mscpcheck")
        response = self.client.get(reverse("turbo:mscp_checks"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, reverse("turbo:delete_mscp_check", args=(mscp_check.pk,)))

    def test_mscp_check_detail(self):
        mscp_check = force_mscp_check()
        self.login("turbo.view_mscpcheck")
        response = self.client.get(mscp_check.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/mscpcheck_detail.html")
        self.assertContains(response, mscp_check.rule_id)

    def test_mscp_check_detail_lists_jobs(self):
        configuration = force_configuration()
        mscp_check = force_mscp_check()
        force_recurring_job(configuration=configuration, job=mscp_check.job)
        self.login("turbo.view_mscpcheck", "turbo.view_recurringjob", "turbo.view_onetimejob")
        response = self.client.get(mscp_check.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Recurring job")
        self.assertContains(response, configuration.get_absolute_url())

    # create mSCP check

    def test_create_mscp_check_redirect(self):
        self.login_redirect("create_mscp_check")

    def test_create_mscp_check_permission_denied(self):
        self.login()
        response = self.client.get(reverse("turbo:create_mscp_check"))
        self.assertEqual(response.status_code, 403)

    def test_create_mscp_check_get(self):
        self.login("turbo.add_mscpcheck")
        response = self.client.get(reverse("turbo:create_mscp_check"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/mscpcheck_form.html")

    def test_create_mscp_check_too_many_odv_error(self):
        self.login("turbo.add_mscpcheck")
        response = self.client.post(reverse("turbo:create_mscp_check"),
                                    {"rule_id": get_random_string(12), "odv_int": "1", "odv_string": "x"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/mscpcheck_form.html")
        self.assertFormError(response.context["form"], "odv_int", "Set at most one ODV override")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_mscp_check_post(self, post_event):
        self.login("turbo.add_mscpcheck", "turbo.view_mscpcheck")
        rule_id = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("turbo:create_mscp_check"),
                                        {"rule_id": rule_id},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/mscpcheck_detail.html")
        mscp_check = response.context["object"]
        self.assertEqual(mscp_check.rule_id, rule_id)
        self.assertEqual(mscp_check.baseline, "")
        self.assertIsNone(mscp_check.odv)
        self.assertEqual(mscp_check.job.kind, "mscp_check")
        self.assertEqual(mscp_check.job.version, 1)
        self.assertEqual(mscp_check.compliance_check.model, "TurboMSCPCheck")
        self.assertEqual(mscp_check.compliance_check.name, rule_id)
        self.assertEqual(mscp_check.compliance_check.version, 1)
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        event = audit_events[0]
        self.assertEqual(event.payload["action"], "created")
        self.assertEqual(event.payload["object"]["model"], "turbo.mscpcheck")
        self.assertEqual(event.payload["object"]["pk"], str(mscp_check.pk))
        self.assertEqual(event.payload["object"]["new_value"]["version"], 1)
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"turbo_mscp_check": [str(mscp_check.pk)]})

    def test_create_mscp_check_baseline_post(self):
        self.login("turbo.add_mscpcheck", "turbo.view_mscpcheck")
        rule_id = get_random_string(12)
        response = self.client.post(reverse("turbo:create_mscp_check"),
                                    {"rule_id": rule_id, "baseline": "cis_lvl1"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        mscp_check = response.context["object"]
        self.assertEqual(mscp_check.baseline, "cis_lvl1")
        self.assertIsNone(mscp_check.odv)
        self.assertEqual(mscp_check.compliance_check.name, f"{rule_id} / cis_lvl1")

    def test_create_mscp_check_baseline_and_odv_rejected(self):
        self.login("turbo.add_mscpcheck", "turbo.view_mscpcheck")
        response = self.client.post(reverse("turbo:create_mscp_check"),
                                    {"rule_id": get_random_string(12), "baseline": "cis_lvl1", "odv_int": "15"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/mscpcheck_form.html")
        self.assertFormError(response.context["form"], "baseline",
                             "Set a baseline or an ODV override, not both")

    def test_mscp_check_baseline_xor_odv_db_constraint(self):
        # the DB CheckConstraint is the backstop behind the form / serializer validation
        with self.assertRaises(IntegrityError), transaction.atomic():
            MSCPCheck.objects.create(rule_id=get_random_string(12), baseline="cis_lvl1", odv_int=15)

    def test_failed_mscp_check_save_leaves_no_orphan_job(self):
        # MSCPCheck.save() is atomic: a failed insert rolls the auto-minted Job + CC back, no orphan
        job_count = Job.objects.count()
        with self.assertRaises(IntegrityError), transaction.atomic():
            MSCPCheck.objects.create(rule_id=get_random_string(12), baseline="cis_lvl1", odv_int=5)
        self.assertEqual(Job.objects.count(), job_count)

    def test_mscp_check_unique_rule_baseline_odv_db_constraint(self):
        # unique(rule_id, baseline, odv_*) is nulls_distinct=False, so two checks with the same rule_id
        # + baseline and no ODV collide (their all-NULL ODVs count as equal, not distinct)
        rule_id = get_random_string(12)
        force_mscp_check(rule_id=rule_id, baseline="cis_lvl1")
        with self.assertRaises(IntegrityError), transaction.atomic():
            force_mscp_check(rule_id=rule_id, baseline="cis_lvl1")

    def test_mscp_check_same_rule_different_odv_allowed(self):
        # the same rule at different ODVs is a different check (ODV is part of identity), not a collision
        rule_id = get_random_string(12)
        force_mscp_check(rule_id=rule_id, odv_int=14)
        force_mscp_check(rule_id=rule_id, odv_int=15)
        self.assertEqual(MSCPCheck.objects.filter(rule_id=rule_id).count(), 2)

    def test_mscp_checks_pagination_reset_link(self):
        force_mscp_check()
        force_mscp_check()
        self.user.items_per_page = 1
        self.user.save()
        self.login("turbo.view_mscpcheck")
        response = self.client.get(reverse("turbo:mscp_checks"), {"page": 2})
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(response.context.get("reset_link"))
        # pagination is rendered both above and below the table
        self.assertEqual(response.content.decode("utf-8").count('aria-label="Page navigation"'), 2)

    def test_create_mscp_check_empty_odv_string_is_no_override(self):
        self.login("turbo.add_mscpcheck", "turbo.view_mscpcheck")
        rule_id = get_random_string(12)
        response = self.client.post(reverse("turbo:create_mscp_check"),
                                    {"rule_id": rule_id, "odv_string": ""},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        mscp_check = response.context["object"]
        self.assertIsNone(mscp_check.odv_string)
        self.assertIsNone(mscp_check.odv)
        self.assertEqual(mscp_check.compliance_check.name, rule_id)

    # update mSCP check

    def test_update_mscp_check_get(self):
        mscp_check = force_mscp_check()
        self.login("turbo.change_mscpcheck")
        response = self.client.get(reverse("turbo:update_mscp_check", args=(mscp_check.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/mscpcheck_form.html")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_mscp_check_bumps_version(self, post_event):
        mscp_check = force_mscp_check(odv_int=10)
        self.assertEqual(mscp_check.job.version, 1)
        cc_pk = mscp_check.compliance_check.pk
        self.login("turbo.change_mscpcheck", "turbo.view_mscpcheck")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("turbo:update_mscp_check", args=(mscp_check.pk,)),
                                        {"rule_id": mscp_check.rule_id, "baseline": "", "odv_int": "20"},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        mscp_check = MSCPCheck.objects.get(pk=mscp_check.pk)
        self.assertEqual(mscp_check.odv_int, 20)
        self.assertEqual(mscp_check.job.version, 2)
        self.assertEqual(mscp_check.compliance_check.pk, cc_pk)
        self.assertEqual(mscp_check.compliance_check.version, 2)
        self.assertEqual(mscp_check.compliance_check.name, f"{mscp_check.rule_id} = 20")
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        self.assertEqual(audit_events[0].payload["action"], "updated")
        self.assertEqual(audit_events[0].payload["object"]["prev_value"]["version"], 1)
        self.assertEqual(audit_events[0].payload["object"]["new_value"]["version"], 2)

    def test_update_mscp_check_no_change_keeps_version(self):
        mscp_check = force_mscp_check(odv_int=10)
        self.login("turbo.change_mscpcheck", "turbo.view_mscpcheck")
        response = self.client.post(reverse("turbo:update_mscp_check", args=(mscp_check.pk,)),
                                    {"rule_id": mscp_check.rule_id, "baseline": "", "odv_int": "10"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        mscp_check = MSCPCheck.objects.get(pk=mscp_check.pk)
        self.assertEqual(mscp_check.job.version, 1)
        self.assertEqual(mscp_check.compliance_check.version, 1)

    # delete mSCP check

    def test_mscp_check_detail_delete_button_hidden_when_scheduled(self):
        mscp_check = force_mscp_check()
        force_recurring_job(job=mscp_check.job)
        self.login("turbo.view_mscpcheck", "turbo.delete_mscpcheck")
        response = self.client.get(mscp_check.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, reverse("turbo:delete_mscp_check", args=(mscp_check.pk,)))

    def test_mscp_check_detail_delete_button_shown_when_not_scheduled(self):
        mscp_check = force_mscp_check()
        self.login("turbo.view_mscpcheck", "turbo.delete_mscpcheck")
        response = self.client.get(mscp_check.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("turbo:delete_mscp_check", args=(mscp_check.pk,)))

    def test_delete_scheduled_mscp_check_404(self):
        mscp_check = force_mscp_check()
        force_recurring_job(job=mscp_check.job)
        self.login("turbo.delete_mscpcheck")
        response = self.client.get(reverse("turbo:delete_mscp_check", args=(mscp_check.pk,)))
        self.assertEqual(response.status_code, 404)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_mscp_check(self, post_event):
        mscp_check = force_mscp_check()
        pk, job_pk, cc_pk = mscp_check.pk, mscp_check.job.pk, mscp_check.compliance_check.pk
        self.login("turbo.delete_mscpcheck", "turbo.view_mscpcheck")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("turbo:delete_mscp_check", args=(pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/mscpcheck_list.html")
        self.assertEqual(MSCPCheck.objects.filter(pk=pk).count(), 0)
        self.assertEqual(Job.objects.filter(pk=job_pk).count(), 0)
        self.assertEqual(ComplianceCheck.objects.filter(pk=cc_pk).count(), 0)
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        self.assertEqual(audit_events[0].payload["action"], "deleted")
        self.assertEqual(audit_events[0].payload["object"]["model"], "turbo.mscpcheck")

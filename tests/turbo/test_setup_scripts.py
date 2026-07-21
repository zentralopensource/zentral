from unittest.mock import patch
from django.db import IntegrityError, transaction
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import Tag
from zentral.contrib.turbo.models import Job, Script
from zentral.core.compliance_checks.models import ComplianceCheck
from .utils import TurboSetupTestCase, force_configuration, force_one_time_job, force_recurring_job, force_script


class TurboSetupScriptsTestCase(TurboSetupTestCase):
    # scripts

    def test_scripts_redirect(self):
        self.login_redirect("scripts")

    def test_scripts_permission_denied(self):
        self.login()
        response = self.client.get(reverse("turbo:scripts"))
        self.assertEqual(response.status_code, 403)

    def test_scripts(self):
        force_script()
        self.login("turbo.view_script")
        response = self.client.get(reverse("turbo:scripts"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/script_list.html")

    def test_scripts_search_by_name(self):
        script = force_script()
        force_script()
        self.login("turbo.view_script")
        response = self.client.get(reverse("turbo:scripts"), {"q": script.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["object_list"]), [script])

    def test_scripts_search_by_configuration(self):
        configuration = force_configuration()
        scheduled = force_script()
        force_recurring_job(configuration=configuration, job=scheduled.job)
        force_script()  # not scheduled anywhere
        self.login("turbo.view_script")
        response = self.client.get(reverse("turbo:scripts"), {"configuration": configuration.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["object_list"]), [scheduled])

    def test_scripts_search_no_result_shows_empty_results(self):
        force_script()
        self.login("turbo.view_script")
        response = self.client.get(reverse("turbo:scripts"), {"q": get_random_string(20)})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["object_list"]), [])
        self.assertContains(response, "We didn't find any item")

    def test_script_list_delete_button_shown_when_not_scheduled(self):
        script = force_script()
        self.login("turbo.view_script", "turbo.delete_script")
        response = self.client.get(reverse("turbo:scripts"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("turbo:delete_script", args=(script.pk,)))

    def test_script_list_delete_button_hidden_when_scheduled(self):
        script = force_script()
        force_recurring_job(job=script.job)
        self.login("turbo.view_script", "turbo.delete_script")
        response = self.client.get(reverse("turbo:scripts"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, reverse("turbo:delete_script", args=(script.pk,)))

    def test_script_list_delete_button_hidden_without_perm(self):
        script = force_script()
        self.login("turbo.view_script")
        response = self.client.get(reverse("turbo:scripts"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, reverse("turbo:delete_script", args=(script.pk,)))

    def test_script_detail(self):
        script = force_script()
        self.login("turbo.view_script")
        response = self.client.get(script.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/script_detail.html")
        self.assertContains(response, script.name)

    def test_script_detail_lists_jobs(self):
        configuration = force_configuration()
        script = force_script()
        force_recurring_job(configuration=configuration, job=script.job)
        force_one_time_job(configuration=configuration, job=script.job)
        self.login("turbo.view_script", "turbo.view_recurringjob", "turbo.view_onetimejob")
        response = self.client.get(script.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Recurring job")
        self.assertContains(response, "One-time job")
        self.assertContains(response, configuration.get_absolute_url())

    def test_script_detail_jobs_hidden_without_permission(self):
        configuration = force_configuration()
        script = force_script()
        force_recurring_job(configuration=configuration, job=script.job)
        self.login("turbo.view_script")
        response = self.client.get(script.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Recurring job")

    # create script

    def test_create_script_redirect(self):
        self.login_redirect("create_script")

    def test_create_script_permission_denied(self):
        self.login()
        response = self.client.get(reverse("turbo:create_script"))
        self.assertEqual(response.status_code, 403)

    def test_create_script_get(self):
        self.login("turbo.add_script")
        response = self.client.get(reverse("turbo:create_script"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/script_form.html")

    def test_create_script_no_arch_error(self):
        self.login("turbo.add_script")
        response = self.client.post(reverse("turbo:create_script"),
                                    {"name": get_random_string(12), "source": "echo ok"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/script_form.html")
        self.assertFormError(response.context["form"], "arch_amd64", "Select at least one architecture")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_script_post(self, post_event):
        self.login("turbo.add_script", "turbo.view_script")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("turbo:create_script"),
                                        {"name": name, "source": "echo ok",
                                         "arch_amd64": "on", "arch_arm64": "on"},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/script_detail.html")
        script = response.context["object"]
        self.assertEqual(script.name, name)
        self.assertEqual(script.job.kind, "script")
        self.assertEqual(script.job.version, 1)
        self.assertIsNone(script.compliance_check)
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        event = audit_events[0]
        self.assertEqual(event.payload["action"], "created")
        self.assertEqual(event.payload["object"]["model"], "turbo.script")
        self.assertEqual(event.payload["object"]["pk"], str(script.pk))
        self.assertEqual(event.payload["object"]["new_value"]["version"], 1)
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"turbo_script": [str(script.pk)]})

    def test_create_script_compliance(self):
        self.login("turbo.add_script", "turbo.view_script")
        name = get_random_string(12)
        response = self.client.post(reverse("turbo:create_script"),
                                    {"name": name, "source": "echo ok",
                                     "arch_amd64": "on", "arch_arm64": "on",
                                     "compliance_check": "on"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        script = response.context["object"]
        self.assertIsNotNone(script.compliance_check)
        self.assertEqual(script.compliance_check.model, "TurboScript")
        self.assertEqual(script.compliance_check.name, name)
        self.assertEqual(script.compliance_check.version, script.job.version)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_script_with_tag(self, post_event):
        tag = Tag.objects.create(name=get_random_string(12))
        self.login("turbo.add_script", "turbo.view_script")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("turbo:create_script"),
                                        {"name": get_random_string(12), "source": "echo ok",
                                         "arch_amd64": "on", "arch_arm64": "on",
                                         "tag": tag.pk},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        script = response.context["object"]
        self.assertEqual(script.tag, tag)
        # the tagging-role target is linked in the audit event
        metadata = self._audit_events(post_event)[0].metadata.serialize()
        self.assertEqual(set(metadata["objects"]), {"turbo_script", "tag"})
        self.assertEqual(metadata["objects"]["turbo_script"], [str(script.pk)])
        self.assertEqual(metadata["objects"]["tag"], [str(tag.pk)])

    # update script

    def test_update_script_get(self):
        script = force_script()
        self.login("turbo.change_script")
        response = self.client.get(reverse("turbo:update_script", args=(script.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/script_form.html")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_script_source_bumps_version(self, post_event):
        script = force_script(compliance_check=True)
        self.assertEqual(script.job.version, 1)
        cc_pk = script.compliance_check.pk
        self.login("turbo.change_script", "turbo.view_script")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("turbo:update_script", args=(script.pk,)),
                                        {"name": script.name, "source": "echo changed",
                                         "arch_amd64": "on", "arch_arm64": "on",
                                         "compliance_check": "on"},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        script = Script.objects.get(pk=script.pk)
        self.assertEqual(script.job.version, 2)
        self.assertEqual(script.compliance_check.pk, cc_pk)
        self.assertEqual(script.compliance_check.version, 2)
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        self.assertEqual(audit_events[0].payload["action"], "updated")
        self.assertEqual(audit_events[0].payload["object"]["prev_value"]["version"], 1)
        self.assertEqual(audit_events[0].payload["object"]["new_value"]["version"], 2)

    def test_update_script_disable_compliance(self):
        script = force_script(compliance_check=True)
        cc_pk = script.compliance_check.pk
        self.login("turbo.change_script", "turbo.view_script")
        response = self.client.post(reverse("turbo:update_script", args=(script.pk,)),
                                    {"name": script.name, "source": script.source,
                                     "arch_amd64": "on", "arch_arm64": "on"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        script = Script.objects.get(pk=script.pk)
        self.assertIsNone(script.compliance_check)
        self.assertEqual(ComplianceCheck.objects.filter(pk=cc_pk).count(), 0)

    def test_script_detail_delete_button_hidden_when_scheduled(self):
        script = force_script()
        force_recurring_job(job=script.job)
        self.login("turbo.view_script", "turbo.delete_script")
        response = self.client.get(script.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, reverse("turbo:delete_script", args=(script.pk,)))

    def test_script_detail_delete_button_shown_when_not_scheduled(self):
        script = force_script()
        self.login("turbo.view_script", "turbo.delete_script")
        response = self.client.get(script.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("turbo:delete_script", args=(script.pk,)))

    # delete script

    def test_delete_scheduled_script_404(self):
        script = force_script()
        force_recurring_job(job=script.job)
        self.login("turbo.delete_script")
        response = self.client.get(reverse("turbo:delete_script", args=(script.pk,)))
        self.assertEqual(response.status_code, 404)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_script(self, post_event):
        script = force_script(compliance_check=True)
        pk, job_pk, cc_pk = script.pk, script.job.pk, script.compliance_check.pk
        self.login("turbo.delete_script", "turbo.view_script")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("turbo:delete_script", args=(pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/script_list.html")
        self.assertEqual(Script.objects.filter(pk=pk).count(), 0)
        self.assertEqual(Job.objects.filter(pk=job_pk).count(), 0)
        self.assertEqual(ComplianceCheck.objects.filter(pk=cc_pk).count(), 0)
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        self.assertEqual(audit_events[0].payload["action"], "deleted")
        self.assertEqual(audit_events[0].payload["object"]["model"], "turbo.script")

    def test_failed_script_save_leaves_no_orphan_job(self):
        # Script.save() is atomic: a duplicate name rolls the auto-minted Job back, no orphan
        script = force_script()
        job_count = Job.objects.count()
        with self.assertRaises(IntegrityError), transaction.atomic():
            Script.objects.create(name=script.name, source="echo dup")
        self.assertEqual(Job.objects.count(), job_count)

    def test_scripts_pagination_reset_link(self):
        force_script()
        force_script()
        self.user.items_per_page = 1
        self.user.save()
        self.login("turbo.view_script")
        response = self.client.get(reverse("turbo:scripts"), {"page": 2})
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(response.context.get("reset_link"))
        # pagination is rendered both above and below the table
        self.assertEqual(response.content.decode("utf-8").count('aria-label="Page navigation"'), 2)

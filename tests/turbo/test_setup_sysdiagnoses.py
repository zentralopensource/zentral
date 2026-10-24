from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.turbo.command_backends import CommandBackend
from .utils import (VIEW_ONE_TIME_JOB_ACTION, VIEW_RECURRING_JOB_ACTION, TurboSetupTestCase, force_command,
                    force_configuration, force_enrolled_machine, force_one_time_job, force_script, turbo_policy)


class TurboSetupSysdiagnosesTestCase(TurboSetupTestCase):
    # list

    def test_sysdiagnoses_redirect(self):
        self.login_redirect("sysdiagnoses")

    def test_sysdiagnoses_permission_denied(self):
        self.login()
        response = self.client.get(reverse("turbo:sysdiagnoses"))
        self.assertEqual(response.status_code, 403)

    def test_sysdiagnoses(self):
        sysdiagnose = force_command()
        force_command(backend=CommandBackend.FILE_EXPORT)
        self.login("turbo.view_sysdiagnose")
        response = self.client.get(reverse("turbo:sysdiagnoses"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/sysdiagnose_list.html")
        self.assertEqual(list(response.context["object_list"]), [sysdiagnose])
        self.assertContains(response, "Sysdiagnose (1)")
        self.assertContains(response, sysdiagnose.get_absolute_url())

    def test_sysdiagnoses_search_by_name(self):
        sysdiagnose = force_command()
        force_command()
        self.login("turbo.view_sysdiagnose")
        response = self.client.get(reverse("turbo:sysdiagnoses"), {"q": sysdiagnose.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["object_list"]), [sysdiagnose])

    def test_sysdiagnoses_search_by_configuration(self):
        configuration = force_configuration()
        scheduled = force_command()
        force_one_time_job(configuration=configuration, job=scheduled.job)
        force_command()  # not scheduled anywhere
        self.login_with_policy(turbo_policy(self.group, "turbo.view_sysdiagnose", "turbo.view_configuration",
                                            actions=(VIEW_ONE_TIME_JOB_ACTION, VIEW_RECURRING_JOB_ACTION)))
        response = self.client.get(reverse("turbo:sysdiagnoses"), {"configuration": configuration.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["object_list"]), [scheduled])

    def test_sysdiagnoses_search_no_result_shows_empty_results(self):
        force_command()
        self.login("turbo.view_sysdiagnose")
        response = self.client.get(reverse("turbo:sysdiagnoses"), {"q": get_random_string(20)})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["object_list"]), [])
        self.assertContains(response, "We didn't find any item")

    def test_sysdiagnoses_none(self):
        self.login("turbo.view_sysdiagnose")
        response = self.client.get(reverse("turbo:sysdiagnoses"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Turbo sysdiagnoses")

    # detail

    def test_sysdiagnose_redirect(self):
        sysdiagnose = force_command()
        self.login_redirect("sysdiagnose", sysdiagnose.pk)

    def test_sysdiagnose_permission_denied(self):
        sysdiagnose = force_command()
        self.login("turbo.view_fileexport")
        response = self.client.get(reverse("turbo:sysdiagnose", args=(sysdiagnose.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_sysdiagnose_detail(self):
        sysdiagnose = force_command()
        self.login("turbo.view_sysdiagnose")
        response = self.client.get(reverse("turbo:sysdiagnose", args=(sysdiagnose.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/sysdiagnose_detail.html")
        self.assertContains(response, sysdiagnose.name)
        # a kind with no options shows no options, and one artifact
        self.assertEqual(response.context["options"], {})
        self.assertEqual([a.name for a in response.context["artifacts"]], ["archive"])

    def test_file_export_detail_not_a_sysdiagnose(self):
        file_export = force_command(backend=CommandBackend.FILE_EXPORT)
        self.login("turbo.view_sysdiagnose")
        response = self.client.get(reverse("turbo:sysdiagnose", args=(file_export.pk,)))
        self.assertEqual(response.status_code, 404)

    def test_sysdiagnose_detail_lists_its_schedules(self):
        # The detail page lists the schedules that run the definition. Every job list links the
        # get_absolute_url of a definition.
        configuration = force_configuration()
        sysdiagnose = force_command()
        one_time_job = force_one_time_job(configuration=configuration, job=sysdiagnose.job)
        self.login_with_policy(turbo_policy(self.group, "turbo.view_sysdiagnose", actions=(VIEW_ONE_TIME_JOB_ACTION,)))
        response = self.client.get(reverse("turbo:sysdiagnose", args=(sysdiagnose.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["one_time_jobs"]), [one_time_job])
        self.assertEqual(list(response.context["recurring_jobs"]), [])
        self.assertContains(response, "One-time job (1)")

    # the one-time job list links every definition, whatever its kind

    def test_one_time_job_list_links_the_sysdiagnose(self):
        configuration = force_configuration()
        sysdiagnose = force_command()
        force_one_time_job(configuration=configuration, job=sysdiagnose.job)
        force_one_time_job(configuration=configuration, job=force_script().job)
        self.login_with_policy(turbo_policy(self.group, actions=(VIEW_ONE_TIME_JOB_ACTION,)))
        response = self.client.get(reverse("turbo:one_time_jobs"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("turbo:sysdiagnose", args=(sysdiagnose.pk,)))
        self.assertContains(response, "<td>Sysdiagnose</td>")

    # menu

    def test_menu_hidden_without_the_permission(self):
        self.login("turbo.view_script")
        response = self.client.get(reverse("turbo:scripts"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, reverse("turbo:sysdiagnoses"))

    def test_menu_shown_with_the_permission(self):
        self.login("turbo.view_script", "turbo.view_sysdiagnose")
        response = self.client.get(reverse("turbo:scripts"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("turbo:sysdiagnoses"))
        self.assertNotContains(response, reverse("turbo:file_exports"))

    def test_machine_one_time_job_form_offers_a_sysdiagnose(self):
        # the one-time paths accept the kind that the recurring path refuses
        sysdiagnose = force_command()
        _, serial_number, _ = force_enrolled_machine(meta_business_unit=self.mbu)
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine"))
        response = self.client.get(
            reverse("turbo:schedule_machine_one_time_job", args=(serial_number,)))
        self.assertEqual(response.status_code, 200)
        self.assertIn(sysdiagnose.job, response.context["form"].fields["job"].queryset)

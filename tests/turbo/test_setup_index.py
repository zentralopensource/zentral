from django.urls import reverse
from .utils import (VIEW_ONE_TIME_JOB_ACTION, VIEW_RECURRING_JOB_ACTION, TurboSetupTestCase,
                    force_configuration, force_enrolled_machine, force_one_time_job, force_recurring_job,
                    force_script, turbo_policy, view_schedule_policy)


class TurboSetupIndexTestCase(TurboSetupTestCase):
    def test_index_redirect(self):
        self.login_redirect("index")

    def test_index_permission_denied_without_module_perms(self):
        self.login()  # authenticated, but no turbo permissions
        response = self.client.get(reverse("turbo:index"))
        self.assertEqual(response.status_code, 403)

    def test_index_shows_event_charts(self):
        self.login("turbo.view_script")  # any turbo module perm reaches the overview
        response = self.client.get(reverse("turbo:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/index.html")
        self.assertContains(response, 'data-app="turbo"')

    def test_index_configurations_hidden_without_view_configuration(self):
        configuration = force_configuration()
        self.login("turbo.view_script")  # module perms, but not view_configuration
        response = self.client.get(reverse("turbo:index"))
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("configurations", response.context)
        self.assertNotContains(response, reverse("turbo:configuration", args=(configuration.pk,)))

    def test_index_shows_configurations_with_aggregates(self):
        configuration = force_configuration()
        script = force_script()
        force_recurring_job(configuration=configuration, job=script.job)
        force_one_time_job(configuration=configuration, job=script.job)
        force_enrolled_machine(configuration=configuration)
        self.login_with_policy(turbo_policy(self.group, "turbo.view_configuration",
                                            actions=(VIEW_ONE_TIME_JOB_ACTION, VIEW_RECURRING_JOB_ACTION)))
        response = self.client.get(reverse("turbo:index"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("turbo:configuration", args=(configuration.pk,)))
        summary = {c["pk"]: c for c in response.context["configurations"]}
        self.assertEqual(summary[configuration.pk]["recurring_job_count"], 1)
        self.assertEqual(summary[configuration.pk]["one_time_job_count"], 1)
        self.assertEqual(summary[configuration.pk]["enrollment_count"], 1)
        self.assertEqual(summary[configuration.pk]["machine_count"], 1)

    def test_index_counts_only_the_visible_schedules(self):
        # a count over hidden schedules would tell that they exist
        configuration = force_configuration()
        other_configuration = force_configuration()
        for schedule_configuration in (configuration, other_configuration):
            script = force_script()
            force_recurring_job(configuration=schedule_configuration, job=script.job)
            force_one_time_job(configuration=schedule_configuration, job=script.job)
        self.login_with_policy(
            turbo_policy(self.group, "turbo.view_configuration", actions=())
            + view_schedule_policy(self.group, scope=f'resource in Turbo::Configuration::"{configuration.pk}"')
        )
        response = self.client.get(reverse("turbo:index"))
        self.assertEqual(response.status_code, 200)
        summary = {c["pk"]: c for c in response.context["configurations"]}
        self.assertEqual(summary[configuration.pk]["recurring_job_count"], 1)
        self.assertEqual(summary[configuration.pk]["one_time_job_count"], 1)
        self.assertEqual(summary[other_configuration.pk]["recurring_job_count"], 0)
        self.assertEqual(summary[other_configuration.pk]["one_time_job_count"], 0)

    def test_breadcrumb_links_back_to_index(self):
        self.login("turbo.view_script")
        response = self.client.get(reverse("turbo:scripts"))
        # the section pages carry a "Turbo" crumb back to the overview
        self.assertContains(response, '<a href="{}">Turbo</a>'.format(reverse("turbo:index")))

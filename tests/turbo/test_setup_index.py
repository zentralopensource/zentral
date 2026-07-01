from django.urls import reverse
from .utils import (TurboSetupTestCase, force_configuration, force_enrolled_machine,
                    force_one_time_job, force_recurring_job, force_script)


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
        self.login("turbo.view_configuration")
        response = self.client.get(reverse("turbo:index"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("turbo:configuration", args=(configuration.pk,)))
        summary = {c["pk"]: c for c in response.context["configurations"]}
        self.assertEqual(summary[configuration.pk]["recurring_job_count"], 1)
        self.assertEqual(summary[configuration.pk]["one_time_job_count"], 1)
        self.assertEqual(summary[configuration.pk]["enrollment_count"], 1)
        self.assertEqual(summary[configuration.pk]["machine_count"], 1)

    def test_breadcrumb_links_back_to_index(self):
        self.login("turbo.view_script")
        response = self.client.get(reverse("turbo:scripts"))
        # the section pages carry a "Turbo" crumb back to the overview
        self.assertContains(response, '<a href="{}">Turbo</a>'.format(reverse("turbo:index")))

from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.turbo.command_backends import CommandBackend
from .utils import (TurboSetupTestCase, force_command, force_configuration, force_enrolled_machine,
                    force_one_time_job, force_script, turbo_policy)


class TurboSetupCommandsTestCase(TurboSetupTestCase):
    # the console is read-only for commands, like it is for stores.Store and probes.Action: a command is
    # defined through the API, where the per-backend kwargs serializer already validates it.

    # list

    def test_commands_redirect(self):
        self.login_redirect("commands")

    def test_commands_permission_denied(self):
        self.login()
        response = self.client.get(reverse("turbo:commands"))
        self.assertEqual(response.status_code, 403)

    def test_commands(self):
        force_command()
        self.login("turbo.view_command")
        response = self.client.get(reverse("turbo:commands"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/command_list.html")

    def test_commands_search_by_name(self):
        command = force_command()
        force_command()
        self.login("turbo.view_command")
        response = self.client.get(reverse("turbo:commands"), {"q": command.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["object_list"]), [command])

    def test_commands_search_by_backend(self):
        force_command(backend=CommandBackend.SYSDIAGNOSE)
        file_export = force_command(backend=CommandBackend.FILE_EXPORT)
        self.login("turbo.view_command")
        response = self.client.get(reverse("turbo:commands"), {"backend": "file_export"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["object_list"]), [file_export])

    def test_commands_search_by_configuration(self):
        configuration = force_configuration()
        scheduled = force_command()
        force_one_time_job(configuration=configuration, job=scheduled.job)
        force_command()  # not scheduled anywhere
        self.login("turbo.view_command")
        response = self.client.get(reverse("turbo:commands"), {"configuration": configuration.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["object_list"]), [scheduled])

    def test_commands_search_no_result_shows_empty_results(self):
        force_command()
        self.login("turbo.view_command")
        response = self.client.get(reverse("turbo:commands"), {"q": get_random_string(20)})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["object_list"]), [])
        self.assertContains(response, "We didn't find any item")

    # detail

    def test_command_redirect(self):
        command = force_command()
        self.login_redirect("command", command.pk)

    def test_command_permission_denied(self):
        command = force_command()
        self.login()
        response = self.client.get(reverse("turbo:command", args=(command.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_sysdiagnose_command_detail(self):
        command = force_command(backend=CommandBackend.SYSDIAGNOSE)
        self.login("turbo.view_command")
        response = self.client.get(reverse("turbo:command", args=(command.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/command_detail.html")
        self.assertContains(response, command.name)
        # a zero-config kind has no kwargs to show, and one artifact
        self.assertEqual(response.context["backend_kwargs"], [])
        self.assertEqual([a.name for a in response.context["artifacts"]], ["archive"])

    def test_file_export_command_detail(self):
        command = force_command(backend=CommandBackend.FILE_EXPORT,
                                backend_kwargs={"patterns": ["/var/log/install.log*"], "max_size": 2048})
        self.login("turbo.view_command")
        response = self.client.get(reverse("turbo:command", args=(command.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["backend_kwargs"],
                         [("max_size", 2048), ("patterns", ["/var/log/install.log*"])])
        self.assertEqual([a.name for a in response.context["artifacts"]], ["manifest", "archive"])
        self.assertContains(response, "/var/log/install.log*")

    def test_command_detail_lists_its_schedules(self):
        # the definition detail page is where the schedules running it are listed — and the reason the
        # page has to exist at all, since every job list links a definition's get_absolute_url
        configuration = force_configuration()
        command = force_command()
        one_time_job = force_one_time_job(configuration=configuration, job=command.job)
        self.login("turbo.view_command")
        response = self.client.get(reverse("turbo:command", args=(command.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["one_time_jobs"]), [one_time_job])
        self.assertEqual(list(response.context["recurring_jobs"]), [])

    # the one-time job list links every definition, whatever its kind

    def test_one_time_job_list_links_the_command(self):
        configuration = force_configuration()
        command = force_command()
        force_one_time_job(configuration=configuration, job=command.job)
        force_one_time_job(configuration=configuration, job=force_script().job)
        self.login("turbo.view_onetimejob")
        response = self.client.get(reverse("turbo:one_time_jobs"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("turbo:command", args=(command.pk,)))

    def test_menu_hidden_without_the_permission(self):
        self.login("turbo.view_script")
        response = self.client.get(reverse("turbo:scripts"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, reverse("turbo:commands"))

    def test_menu_shown_with_the_permission(self):
        self.login("turbo.view_command")
        response = self.client.get(reverse("turbo:commands"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("turbo:commands"))

    def test_machine_one_time_job_form_offers_a_command(self):
        # the one-time paths must offer what the recurring path refuses
        command = force_command()
        _, serial_number, _ = force_enrolled_machine(meta_business_unit=self.mbu)
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine"))
        response = self.client.get(
            reverse("turbo:schedule_machine_one_time_job", args=(serial_number,)))
        self.assertEqual(response.status_code, 200)
        self.assertIn(command.job, response.context["form"].fields["job"].queryset)

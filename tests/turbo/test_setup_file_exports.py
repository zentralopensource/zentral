from django.urls import reverse
from zentral.contrib.turbo.command_backends import CommandBackend
from .utils import TurboSetupTestCase, force_command, force_configuration, force_one_time_job


class TurboSetupFileExportsTestCase(TurboSetupTestCase):
    def _force_file_export(self):
        return force_command(backend=CommandBackend.FILE_EXPORT,
                             backend_kwargs={"patterns": ["/var/log/install.log*", "/Library/Logs/*/*.log"],
                                             "max_size": 2097152})

    # list

    def test_file_exports_redirect(self):
        self.login_redirect("file_exports")

    def test_file_exports_permission_denied(self):
        self.login("turbo.view_sysdiagnose")
        response = self.client.get(reverse("turbo:file_exports"))
        self.assertEqual(response.status_code, 403)

    def test_file_exports(self):
        file_export = self._force_file_export()
        force_command(backend=CommandBackend.SYSDIAGNOSE)
        self.login("turbo.view_fileexport")
        response = self.client.get(reverse("turbo:file_exports"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/fileexport_list.html")
        self.assertEqual(list(response.context["object_list"]), [file_export])
        self.assertContains(response, "File export (1)")
        self.assertContains(response, file_export.get_absolute_url())

    def test_file_exports_search_by_configuration(self):
        configuration = force_configuration()
        scheduled = self._force_file_export()
        force_one_time_job(configuration=configuration, job=scheduled.job)
        self._force_file_export()
        self.login("turbo.view_fileexport")
        response = self.client.get(reverse("turbo:file_exports"), {"configuration": configuration.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["object_list"]), [scheduled])

    # detail

    def test_file_export_redirect(self):
        file_export = self._force_file_export()
        self.login_redirect("file_export", file_export.pk)

    def test_file_export_permission_denied(self):
        file_export = self._force_file_export()
        self.login("turbo.view_sysdiagnose")
        response = self.client.get(reverse("turbo:file_export", args=(file_export.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_file_export_detail(self):
        file_export = self._force_file_export()
        self.login("turbo.view_fileexport")
        response = self.client.get(reverse("turbo:file_export", args=(file_export.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/fileexport_detail.html")
        self.assertEqual(response.context["options"],
                         {"patterns": ["/var/log/install.log*", "/Library/Logs/*/*.log"], "max_size": 2097152})
        self.assertEqual([a.name for a in response.context["artifacts"]], ["manifest", "archive"])
        self.assertContains(response, "<code>/var/log/install.log*</code><br>", html=False)
        self.assertContains(response, "<code>/Library/Logs/*/*.log</code><br>", html=False)
        self.assertContains(response, "2.0\xa0MB (2097152 bytes)")

    # menu

    def test_menu_shown_with_the_permission(self):
        self.login("turbo.view_fileexport")
        response = self.client.get(reverse("turbo:file_exports"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("turbo:file_exports"))
        self.assertNotContains(response, reverse("turbo:sysdiagnoses"))

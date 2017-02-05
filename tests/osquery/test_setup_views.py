from django.core.urlresolvers import reverse
from django.test import TestCase, override_settings
from zentral.contrib.inventory.models import MetaBusinessUnit
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class OsquerySetupViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.pwd = "godzillapwd"
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", cls.pwd)

    def login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def log_user_in(self):
        response = self.client.post(reverse('login'),
                                    {'username': self.user.username, 'password': self.pwd},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["user"], self.user)

    def log_user_out(self):
        response = self.client.get(reverse('logout'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["user"].is_authenticated(), False)

    def test_enrollment_redirect(self):
        self.login_redirect(reverse("osquery:enrollment"))

    def test_enrollment_view(self):
        self.log_user_in()
        response = self.client.get(reverse("osquery:enrollment"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/enrollment.html")
        self.assertContains(response, "Osquery enrollment")
        # doesn't list mbu without api enrollment
        mbu_name = "Moby-Dick"
        mbu = MetaBusinessUnit.objects.create(name=mbu_name)
        response = self.client.get(reverse("osquery:enrollment"))
        self.assertNotContains(response, mbu_name)
        # list mbu with api enrollment
        mbu.create_enrollment_business_unit()
        response = self.client.get(reverse("osquery:enrollment"))
        self.assertContains(response, mbu_name)

    def test_enrollment_debugging_view_redirect(self):
        self.login_redirect(reverse("osquery:enrollment_debugging"))

    def test_enrollment_debugging_view(self):
        self.log_user_in()
        response = self.client.get(reverse("osquery:enrollment_debugging"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "curl ")
        self.assertContains(response, "enroll_secret")

    def test_installer_package_view_redirect(self):
        url = reverse("osquery:installer_package")
        response = self.client.post(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def test_installer_package_view(self):
        self.log_user_in()
        # without mbu
        response = self.client.post(reverse("osquery:installer_package"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "application/octet-stream")
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="zentral_osquery_enroll.pkg"')
        # with mbu
        mbu = MetaBusinessUnit.objects.create(name="zu")
        response = self.client.post(reverse("osquery:installer_package"),
                                    {"meta_business_unit": mbu.pk})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, "form", "meta_business_unit",
                             "Select a valid choice. "
                             "That choice is not one of the available choices.")
        # enable api
        mbu.create_enrollment_business_unit()
        response = self.client.post(reverse("osquery:installer_package"),
                                    {"meta_business_unit": mbu.pk})
        self.assertEqual(response.status_code, 200)

    def test_setup_script_view_redirect(self):
        self.login_redirect(reverse("osquery:setup_script"))

    def test_setup_script_view(self):
        self.log_user_in()
        response = self.client.post(reverse("osquery:setup_script"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "text/x-shellscript")
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="osquery_zentral_setup.sh"')
        # with mbu
        mbu = MetaBusinessUnit.objects.create(name="uz")
        response = self.client.post(reverse("osquery:setup_script"),
                                    {"meta_business_unit": mbu.pk})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, "form", "meta_business_unit",
                             "Select a valid choice. "
                             "That choice is not one of the available choices.")
        # enable api
        mbu.create_enrollment_business_unit()
        response = self.client.post(reverse("osquery:setup_script"),
                                    {"meta_business_unit": mbu.pk})
        self.assertEqual(response.status_code, 200)

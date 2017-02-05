from django.core.urlresolvers import reverse
from django.test import TestCase, override_settings
from zentral.contrib.inventory.models import MetaBusinessUnit
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class SantaSetupViewsTestCase(TestCase):
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
        self.login_redirect(reverse("santa:enrollment"))

    def test_enrollment_view(self):
        self.log_user_in()
        response = self.client.get(reverse("santa:enrollment"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/enrollment.html")
        self.assertContains(response, "Santa enrollment")
        # doesn't list mbu without api enrollment
        mbu_name = "Moby-Dick"
        mbu = MetaBusinessUnit.objects.create(name=mbu_name)
        response = self.client.get(reverse("santa:enrollment"))
        self.assertNotContains(response, mbu_name)
        # list mbu with api enrollment
        mbu.create_enrollment_business_unit()
        response = self.client.get(reverse("santa:enrollment"))
        self.assertContains(response, mbu_name)

    def test_enrollment_debugging_view_redirect(self):
        self.login_redirect(reverse("santa:enrollment_debugging"))

    def test_enrollment_debugging_view(self):
        self.log_user_in()
        response = self.client.get(reverse("santa:enrollment_debugging"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "curl -XPOST -k https://")
        self.assertContains(response, "machine_id=")

    def test_installer_package_view_redirect(self):
        url = reverse("santa:installer_package")
        response = self.client.post(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def test_installer_package_view(self):
        self.log_user_in()
        # without mbu
        response = self.client.post(reverse("santa:installer_package"),
                                    {"mode": 1})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "application/octet-stream")
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="zentral_santa_enroll.pkg"')
        # without mode
        response = self.client.post(reverse("santa:installer_package"))
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, "form", "mode", "This field is required.")
        # with wrong mode
        response = self.client.post(reverse("santa:installer_package"),
                                    {"mode": 3})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, "form", "mode",
                             "Select a valid choice. "
                             "3 is not one of the available choices.")
        # with mbu
        mbu = MetaBusinessUnit.objects.create(name="zu")
        response = self.client.post(reverse("santa:installer_package"),
                                    {"meta_business_unit": mbu.pk,
                                     "mode": 1})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, "form", "meta_business_unit",
                             "Select a valid choice. "
                             "That choice is not one of the available choices.")
        # enable api
        mbu.create_enrollment_business_unit()
        response = self.client.post(reverse("santa:installer_package"),
                                    {"meta_business_unit": mbu.pk,
                                     "mode": 2})
        self.assertEqual(response.status_code, 200)

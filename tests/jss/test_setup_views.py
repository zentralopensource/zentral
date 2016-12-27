from django.core.urlresolvers import reverse
from django.test import TestCase, override_settings
from zentral.contrib.inventory.models import MetaBusinessUnit
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class JssSetupViewsTestCase(TestCase):
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
        self.login_redirect(reverse("jss:enrollment"))

    def test_enrollment_view(self):
        self.log_user_in()
        response = self.client.get(reverse("jss:enrollment"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "jss/enrollment.html")
        self.assertContains(response, "JSS enrollment")
        # doesn't list mbu without api enrollment
        mbu_name = "Moby-Dick"
        mbu = MetaBusinessUnit.objects.create(name=mbu_name)
        response = self.client.get(reverse("jss:enrollment"))
        self.assertNotContains(response, mbu_name)
        # list mbu with api enrollment
        mbu.create_enrollment_business_unit()
        response = self.client.get(reverse("jss:enrollment"))
        self.assertContains(response, mbu_name)

    def test_enrollment_debugging_view_redirect(self):
        self.login_redirect(reverse("jss:enrollment_debugging"))

    def test_enrollment_debugging_view(self):
        self.log_user_in()
        response = self.client.get(reverse("jss:enrollment_debugging"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "webhook_url=https://")

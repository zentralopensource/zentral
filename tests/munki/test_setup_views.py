import json
import uuid
from django.urls import reverse
from django.test import TestCase, override_settings
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.munki.models import EnrolledMachine
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MunkiSetupViewsTestCase(TestCase):
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
        self.assertEqual(response.context["user"].is_authenticated, False)

    def post_as_json(self, url_name, data):
        return self.client.post(reverse("munki:{}".format(url_name)),
                                json.dumps(data),
                                content_type="application/json")

    def test_enrollments_redirect(self):
        self.login_redirect(reverse("munki:enrollment_list"))
        self.login_redirect(reverse("munki:create_enrollment"))

    def test_get_create_enrollment_view(self):
        self.log_user_in()
        response = self.client.get(reverse("munki:create_enrollment"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/enrollment_form.html")
        self.assertContains(response, "Munki enrollment")

    def create_enrollment(self):
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
        mbu.create_enrollment_business_unit()
        response = self.client.post(reverse("munki:create_enrollment"),
                                    {"secret-meta_business_unit": mbu.pk}, follow=True)
        enrollment = response.context["object_list"][0]
        return response, enrollment

    def test_post_create_enrollment_view(self):
        self.log_user_in()
        # without mbu
        response, enrollment = self.create_enrollment()
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/enrollment_list.html")
        self.assertContains(response, enrollment.secret.meta_business_unit.name)

    def test_enrollment_package_view(self):
        self.log_user_in()
        _, enrollment = self.create_enrollment()
        self.log_user_out()
        enrollment_package_url = reverse("munki:enrollment_package", args=(enrollment.pk,))
        self.login_redirect(enrollment_package_url)
        self.log_user_in()
        response = self.client.get(enrollment_package_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "application/octet-stream")
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="zentral_munki_enroll.pkg"')

    def test_enroll_view(self):
        self.log_user_in()
        _, enrollment = self.create_enrollment()
        self.log_user_out()
        response = self.post_as_json("enroll", {})
        self.assertEqual(response.status_code, 400)
        machine_serial_number = get_random_string(32)
        response = self.post_as_json("enroll", {"secret": "yolo",
                                                "uuid": str(uuid.uuid4()),
                                                "serial_number": machine_serial_number})
        self.assertEqual(response.status_code, 400)
        response = self.post_as_json("enroll", {"secret": enrollment.secret.secret,
                                                "uuid": str(uuid.uuid4()),
                                                "serial_number": machine_serial_number})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "application/json")
        json_response = response.json()
        self.assertCountEqual(["token"], json_response.keys())
        token = json_response["token"]
        enrolled_machine = EnrolledMachine.objects.get(enrollment=enrollment,
                                                       serial_number=machine_serial_number)
        self.assertEqual(token, enrolled_machine.token)

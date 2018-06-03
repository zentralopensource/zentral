import json
from django.core.urlresolvers import reverse
from django.test import TestCase, override_settings
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.santa.models import EnrolledMachine
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

    def post_as_json(self, url_name, data):
        return self.client.post(reverse("santa:{}".format(url_name)),
                                json.dumps(data),
                                content_type="application/json")

    def test_configurations_redirect(self):
        self.login_redirect(reverse("santa:configuration_list"))
        self.login_redirect(reverse("santa:create_configuration"))

    def test_get_create_configuration_view(self):
        self.log_user_in()
        response = self.client.get(reverse("santa:create_configuration"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_form.html")
        self.assertContains(response, "Santa configuration")

    def create_configuration(self):
        response = self.client.post(reverse("santa:create_configuration"),
                                    {"name": get_random_string(64),
                                     "batch_size": 50,
                                     "client_mode": "1",
                                     "banned_block_message": "yo",
                                     "enable_page_zero_protection": "on",
                                     "mode_notification_lockdown": "lockdown",
                                     "mode_notification_monitor": "monitor",
                                     "unknown_block_message": "block",
                                     }, follow=True)
        configuration = response.context["object"]
        return response, configuration

    def test_post_create_configuration_view(self):
        self.log_user_in()
        # without mbu
        response, configuration = self.create_configuration()
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_detail.html")
        self.assertContains(response, configuration.name)

    def test_get_create_enrollment_view(self):
        self.log_user_in()
        _, configuration = self.create_configuration()
        response = self.client.get(reverse("santa:create_enrollment", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/enrollment_form.html")
        self.assertContains(response, "Create enrollment")
        self.assertContains(response, configuration.name)

    def create_enrollment(self, configuration):
        mbu = MetaBusinessUnit.objects.create(name="{} MBU".format(configuration.name))
        mbu.create_enrollment_business_unit()
        response = self.client.post(reverse("santa:create_enrollment", args=(configuration.pk,)),
                                    {"secret-meta_business_unit": mbu.pk,
                                     "configuration": configuration.pk,
                                     "santa_release": ""}, follow=True)
        enrollment = response.context["enrollments"][0]
        self.assertEqual(enrollment.version, 1)
        return response, enrollment

    def test_post_create_enrollment_view(self):
        self.log_user_in()
        _, configuration = self.create_configuration()
        response, enrollment = self.create_enrollment(configuration)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/configuration_detail.html")
        self.assertEqual(response.context["object"], configuration)
        # response contains enrollment secret meta business unit name
        self.assertContains(response, enrollment.secret.meta_business_unit.name)
        # response contains link to download enrollment package
        self.assertContains(response, reverse("santa:enrollment_package", args=(configuration.pk, enrollment.pk)))

    def test_enrollment_package_view(self):
        self.log_user_in()
        _, configuration = self.create_configuration()
        _, enrollment = self.create_enrollment(configuration)
        self.log_user_out()
        enrollment_package_url = reverse("santa:enrollment_package", args=(configuration.pk, enrollment.pk))
        self.login_redirect(enrollment_package_url)
        self.log_user_in()
        response = self.client.get(enrollment_package_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "application/octet-stream")
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="zentral_santa_enroll.pkg"')

    def test_enroll_view(self):
        self.log_user_in()
        _, configuration = self.create_configuration()
        _, enrollment = self.create_enrollment(configuration)
        self.log_user_out()
        response = self.post_as_json("enroll", {})
        self.assertEqual(response.status_code, 400)
        machine_serial_number = get_random_string(32)
        response = self.post_as_json("enroll",
                                     {"secret": "yolo",
                                      "serial_number": machine_serial_number})
        self.assertEqual(response.status_code, 400)
        response = self.post_as_json("enroll",
                                     {"secret": enrollment.secret.secret,
                                      "serial_number": machine_serial_number})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], "application/json")
        json_response = response.json()
        self.assertCountEqual(["machine_id", "config_plist", "configuration_profile"],
                              json_response.keys())
        machine_id = json_response["machine_id"]
        enrolled_machine = EnrolledMachine.objects.get(enrollment=enrollment,
                                                       serial_number=machine_serial_number)
        self.assertEqual(machine_id, enrolled_machine.machine_id)

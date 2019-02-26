import json
import uuid
from django.urls import reverse
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit, EnrollmentSecret
from zentral.contrib.monolith.models import Configuration, EnrolledMachine, Enrollment, Manifest


class MonolithSetupViewsTestCase(TestCase):
    def post_as_json(self, url_name, data):
        return self.client.post(reverse("monolith:{}".format(url_name)),
                                json.dumps(data),
                                content_type="application/json")

    def create_enrollment(self):
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
        mbu.create_enrollment_business_unit()
        secret = EnrollmentSecret.objects.create(meta_business_unit=mbu)
        configuration = Configuration.objects.create(name=get_random_string(64))
        manifest = Manifest.objects.create(meta_business_unit=mbu)
        return Enrollment.objects.create(secret=secret, manifest=manifest, configuration=configuration)

    def test_enroll_view(self):
        enrollment = self.create_enrollment()
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

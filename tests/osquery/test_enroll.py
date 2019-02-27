from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import BusinessUnit, EnrollmentSecret, MachineTag, MetaBusinessUnit, Tag
from zentral.contrib.osquery.models import enroll, Configuration, Enrollment


class OsqueryEnrollmentTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.configuration = Configuration.objects.create(name=get_random_string(256))
        cls.meta_business_unit = MetaBusinessUnit.objects.create(name=get_random_string(64))
        cls.business_unit = cls.meta_business_unit.create_enrollment_business_unit()
        cls.tags = [Tag.objects.create(name="Tag {}".format(get_random_string(7)))
                    for i in range(3)]
        cls.enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=cls.meta_business_unit)
        cls.enrollment_secret.tags.set(cls.tags)
        cls.enrollment = Enrollment.objects.create(configuration=cls.configuration,
                                                   secret=cls.enrollment_secret)

    def test_enroll(self):
        machine_serial_number = get_random_string(64)
        ms, action = enroll(self.enrollment, machine_serial_number, None, "godzilla", "192.168.1.1")
        self.assertEqual(action, "enrollment")
        self.assertEqual(ms.serial_number, machine_serial_number)
        self.assertEqual(ms.public_ip_address, "192.168.1.1")
        self.assertEqual(ms.system_info.computer_name, "godzilla")
        self.assertEqual(set(mt.tag for mt in MachineTag.objects.filter(serial_number=machine_serial_number)),
                         set(self.tags))

    def test_re_enroll(self):
        bu, _ = BusinessUnit.objects.commit({"name": "yo",
                                             "reference": "yo",
                                             "source": {"module": "io.zentral.tests",
                                                        "name": "tests"}})
        machine_serial_number = get_random_string(64)
        ms, action = enroll(self.enrollment, machine_serial_number, bu, "godzilla", "192.168.1.1")
        self.assertEqual(action, "enrollment")
        ms2, action2 = enroll(self.enrollment, machine_serial_number, bu, "godzilla", "192.168.1.1")
        self.assertEqual(ms, ms2)
        self.assertEqual(action2, "re-enrollment")
        self.assertEqual(ms.business_unit, bu)

    def test_re_enroll_mit_update(self):
        machine_serial_number = get_random_string(64)
        ms, action = enroll(self.enrollment, machine_serial_number, None, "godzilla", "192.168.1.1")
        ms2, action2 = enroll(self.enrollment, machine_serial_number, None, "godzilla", "192.168.1.1")
        ms3, action3 = enroll(self.enrollment, machine_serial_number, None, "godzilla", "192.168.1.167")
        self.assertEqual(ms3.machinesnapshotcommit_set.all()[0].parent.machine_snapshot, ms2)
        self.assertEqual(ms3.public_ip_address, "192.168.1.167")
        self.assertEqual(action3, "re-enrollment")

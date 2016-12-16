from django.test import TestCase
from zentral.contrib.inventory.models import BusinessUnit
from zentral.contrib.osquery.models import enroll


class OsqueryEnrollmentTestCase(TestCase):
    def test_enroll(self):
        ms, action = enroll("0123456789", None, "godzilla", "192.168.1.1")
        self.assertEqual(action, "enrollment")
        self.assertEqual(ms.serial_number, "0123456789")
        self.assertEqual(ms.public_ip_address, "192.168.1.1")
        self.assertEqual(ms.system_info.computer_name, "godzilla")

    def test_re_enroll(self):
        bu, _ = BusinessUnit.objects.commit({"name": "yo",
                                             "reference": "yo",
                                             "source": {"module": "io.zentral.tests",
                                                        "name": "tests"}})
        ms, action = enroll("0123456789", bu, "godzilla", "192.168.1.1")
        self.assertEqual(action, "enrollment")
        ms2, action2 = enroll("0123456789", bu, "godzilla", "192.168.1.1")
        self.assertEqual(ms, ms2)
        self.assertEqual(action2, "re-enrollment")
        self.assertEqual(ms.business_unit, bu)

    def test_re_enroll_mit_update(self):
        ms, action = enroll("0123456789", None, "godzilla", "192.168.1.1")
        ms2, action2 = enroll("0123456789", None, "godzilla", "192.168.1.1")
        ms3, action3 = enroll("0123456789", None, "godzilla", "192.168.1.167")
        self.assertEqual(ms3.machinesnapshotcommit_set.all()[0].parent.machine_snapshot, ms2)
        self.assertEqual(ms3.public_ip_address, "192.168.1.167")
        self.assertEqual(action3, "re-enrollment")

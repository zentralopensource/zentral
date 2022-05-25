from datetime import datetime
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.core.compliance_checks.models import ComplianceCheck, MachineStatus, Status
from zentral.core.compliance_checks.utils import update_machine_statuses


class ComplianceChecksTestCase(TestCase):
    def _force_compliance_check(self):
        return ComplianceCheck.objects.create(
            name=get_random_string(12),
            model=get_random_string(12),
        )

    def test_status_total_ordering(self):
        self.assertTrue(Status.OK <= Status.PENDING)

    def test_update_machine_statuses_create_two(self):
        cc1 = self._force_compliance_check()
        cc2 = self._force_compliance_check()
        serial_number = get_random_string(12)
        result = update_machine_statuses(serial_number, [(cc1, Status.OK, datetime.utcnow()),
                                                         (cc2, Status.FAILED, datetime.utcnow())])
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], (cc1.pk, Status.OK.value, None))
        self.assertEqual(result[1], (cc2.pk, Status.FAILED.value, None))
        self.assertEqual(MachineStatus.objects.filter(serial_number=serial_number).count(), 2)

    def test_update_machine_statuses_to_old_noop(self):
        cc1 = self._force_compliance_check()
        serial_number = get_random_string(12)
        status_time = datetime.utcnow()
        ms = MachineStatus.objects.create(
            compliance_check=cc1,
            compliance_check_version=cc1.version,
            serial_number=serial_number,
            status=Status.OK.value,
            status_time=status_time
        )
        result = update_machine_statuses(serial_number, [(cc1, Status.FAILED, datetime(1871, 3, 18))])
        # noop
        self.assertEqual(len(result), 0)
        ms_qs = MachineStatus.objects.filter(serial_number=serial_number)
        self.assertEqual(ms_qs.count(), 1)
        self.assertEqual(ms_qs.first(), ms)
        ms.refresh_from_db()
        self.assertEqual(ms.status, Status.OK.value)
        self.assertEqual(ms.status_time, status_time)

    def test_update_machine_statuses_update_two_no_changes(self):
        cc1 = self._force_compliance_check()
        cc2 = self._force_compliance_check()
        serial_number = get_random_string(12)
        update_machine_statuses(serial_number, [(cc1, Status.OK, None), (cc2, Status.FAILED, datetime.utcnow())])
        result = update_machine_statuses(serial_number, [(cc1, Status.OK, None), (cc2, Status.FAILED, None)])
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], (cc1.pk, Status.OK.value, Status.OK.value))
        self.assertEqual(result[1], (cc2.pk, Status.FAILED.value, Status.FAILED.value))
        self.assertEqual(MachineStatus.objects.filter(serial_number=serial_number).count(), 2)

    def test_update_machine_statuses_update_two_one_change(self):
        cc1 = self._force_compliance_check()
        cc2 = self._force_compliance_check()
        serial_number = get_random_string(12)
        update_machine_statuses(serial_number, [(cc1, Status.OK, datetime.utcnow()), (cc2, Status.FAILED, None)])
        result = update_machine_statuses(serial_number, [(cc1, Status.FAILED, None), (cc2, Status.FAILED, None)])
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], (cc1.pk, Status.FAILED.value, Status.OK.value))
        self.assertEqual(result[1], (cc2.pk, Status.FAILED.value, Status.FAILED.value))
        self.assertEqual(MachineStatus.objects.filter(serial_number=serial_number).count(), 2)

    def test_update_machine_statuses_create_one_then_another_one(self):
        cc1 = self._force_compliance_check()
        serial_number = get_random_string(12)
        result = update_machine_statuses(serial_number, [(cc1, Status.OK, datetime.utcnow())])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], (cc1.pk, Status.OK.value, None))
        self.assertEqual(MachineStatus.objects.filter(serial_number=serial_number).count(), 1)
        serial_number = get_random_string(12)
        result = update_machine_statuses(serial_number, [(cc1, Status.OK, datetime.utcnow())])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], (cc1.pk, Status.OK.value, None))
        self.assertEqual(MachineStatus.objects.filter(serial_number=serial_number).count(), 1)

    def test_update_machine_statuses_version_update(self):
        cc1 = self._force_compliance_check()
        self.assertEqual(cc1.version, 1)
        serial_number = get_random_string(12)
        result = update_machine_statuses(serial_number, [(cc1, Status.OK, datetime.utcnow())])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], (cc1.pk, Status.OK.value, None))
        ms_qs = MachineStatus.objects.filter(serial_number=serial_number)
        self.assertEqual(ms_qs.count(), 1)
        ms = ms_qs.first()
        self.assertEqual(ms.compliance_check_version, cc1.version)
        cc1.version = 2
        cc1.save()
        result = update_machine_statuses(serial_number, [(cc1, Status.OK, datetime.utcnow())])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], (cc1.pk, Status.OK.value, Status.OK.value))
        ms.refresh_from_db()
        self.assertEqual(ms.compliance_check_version, cc1.version)

    def test_update_machine_statuses_status_default_time_update(self):
        cc1 = self._force_compliance_check()
        serial_number = get_random_string(12)
        first_status_time = datetime(2014, 10, 26)
        ms = MachineStatus.objects.create(
            compliance_check=cc1,
            compliance_check_version=cc1.version,
            serial_number=serial_number,
            status=Status.OK.value,
            status_time=first_status_time
        )
        update_machine_statuses(serial_number, [(cc1, Status.OK, None)])
        ms.refresh_from_db()
        self.assertTrue(ms.status_time > first_status_time)

    def test_update_machine_statuses_status_time_update(self):
        cc1 = self._force_compliance_check()
        serial_number = get_random_string(12)
        first_status_time = datetime(2014, 10, 26)
        ms = MachineStatus.objects.create(
            compliance_check=cc1,
            compliance_check_version=cc1.version,
            serial_number=serial_number,
            status=Status.OK.value,
            status_time=first_status_time
        )
        update_machine_statuses(serial_number, [(cc1, Status.OK, datetime(2021, 5, 1))])
        ms.refresh_from_db()
        self.assertTrue(ms.status_time, datetime(2021, 5, 1))

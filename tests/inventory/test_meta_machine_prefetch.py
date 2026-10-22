from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MachineSnapshotCommit, MetaBusinessUnit, MetaMachine


class MetaMachinePrefetchTestCase(TestCase):
    @staticmethod
    def _commit(serial_number, source_name, business_unit_tree=None):
        tree = {"source": {"module": "tests.zentral.io", "name": source_name}, "serial_number": serial_number}
        if business_unit_tree:
            tree["business_unit"] = business_unit_tree
        MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)

    def test_the_same_meta_business_units_as_the_property(self):
        two_business_units = get_random_string(12)
        for name in ("a", "b"):
            self._commit(two_business_units, name,
                         {"name": name, "reference": name, "source": {"module": "tests.zentral.io", "name": name}})
        api_enrollment = get_random_string(12)
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        mbu.create_enrollment_business_unit()
        self._commit(api_enrollment, "c", mbu.api_enrollment_business_units().first().serialize())
        no_business_unit = get_random_string(12)
        self._commit(no_business_unit, "a")
        no_snapshot = get_random_string(12)
        serial_numbers = [two_business_units, api_enrollment, no_business_unit, no_snapshot]
        machines = [MetaMachine(serial_number) for serial_number in serial_numbers]
        with CaptureQueriesContext(connection) as queries:
            MetaMachine.prefetch_meta_business_units(machines)
            prefetched = [machine.meta_business_units for machine in machines]
        self.assertEqual(len(queries.captured_queries), 1)
        self.assertEqual(prefetched, [MetaMachine(serial_number).meta_business_units
                                      for serial_number in serial_numbers])
        self.assertEqual(len(prefetched[0]), 2)
        self.assertEqual(prefetched[1], {mbu})
        self.assertEqual(prefetched[2:], [set(), set()])

    def test_a_machine_with_its_meta_business_units_is_skipped(self):
        machine = MetaMachine(get_random_string(12))
        machine.meta_business_units
        with self.assertNumQueries(0):
            MetaMachine.prefetch_meta_business_units([machine])

    def test_no_machines(self):
        with self.assertNumQueries(0):
            MetaMachine.prefetch_meta_business_units([])

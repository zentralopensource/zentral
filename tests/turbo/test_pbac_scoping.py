from cedarpy import format_policies
from django.contrib.auth.models import Group
from django.test import TestCase
from django.utils.crypto import get_random_string

from accounts.models import Policy, User
from pbac.cedar import policies_cache
from pbac.engine import engine
from pbac.scoping import scope_queryset
from zentral.contrib.inventory.models import MachineSnapshotCommit, MetaBusinessUnit, MetaMachine
from zentral.contrib.turbo.command_backends import CommandBackend
from zentral.contrib.turbo.models import OneTimeJobMachine, RecurringJobMachine
from zentral.contrib.turbo.pbac import ViewOneTimeJobMachineRequest, ViewRecurringJobMachineRequest

from .utils import (force_command, force_configuration, force_mscp_check, force_one_time_job, force_recurring_job,
                    force_script)


WHEN_UNLESS = ("when", "unless")


class TurboPBACScopingTestCase(TestCase):
    """The SQL filter must give the rows that one decision for each row gives, for every policy set."""

    maxDiff = None

    @classmethod
    def _commit(cls, serial_number, source, business_unit=None):
        tree = {"source": {"module": "tests.turbo", "name": source}, "serial_number": serial_number}
        if business_unit:
            tree["business_unit"] = business_unit
        _, machine_snapshot, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        return machine_snapshot

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(get_random_string(12), f"{get_random_string(12)}@zentral.com")
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.add(cls.group)

        # meta business units: one with its API enrollment business unit, two from an inventory source
        cls.mbu_a = MetaBusinessUnit.objects.create(name=get_random_string(12))
        bu_a = cls.mbu_a.create_enrollment_business_unit().serialize()
        bu_b = {"source": {"module": "tests.turbo", "name": "bus"}, "reference": "b", "name": get_random_string(12)}
        bu_c = {"source": {"module": "tests.turbo", "name": "bus"}, "reference": "c", "name": get_random_string(12)}

        # machines
        s = cls.serial_numbers = [get_random_string(12) for _ in range(8)]
        s[6] = f"{get_random_string(6)}/{get_random_string(6)}"  # an encoded entity id
        cls._commit(s[0], "x", bu_a)
        cls.mbu_b = cls._commit(s[1], "x", bu_b).business_unit.meta_business_unit
        cls._commit(s[2], "x", bu_a)
        cls._commit(s[2], "y", bu_b)
        # s[3]: no snapshot, so no meta business unit
        cls._commit(s[4], "x")  # no business unit
        cls._commit(s[5], "x", bu_a)  # not current anymore
        cls.mbu_c = cls._commit(s[5], "x", bu_c).business_unit.meta_business_unit
        cls._commit(s[6], "x", bu_b)
        cls._commit(s[7], "y", bu_c)

        # jobs
        cls.c1 = force_configuration()
        cls.c2 = force_configuration()
        sysdiagnose = force_command(backend=CommandBackend.SYSDIAGNOSE).job
        file_export = force_command(backend=CommandBackend.FILE_EXPORT).job
        script = force_script().job
        mscp_check = force_mscp_check().job
        cls.o1 = force_one_time_job(configuration=cls.c1, job=sysdiagnose)
        cls.o2 = force_one_time_job(configuration=cls.c1, job=file_export)
        cls.o3 = force_one_time_job(configuration=cls.c2, job=script)
        for one_time_job, indexes in ((cls.o1, range(8)), (cls.o2, (0, 2, 4, 6)), (cls.o3, (1, 3, 5, 7))):
            for index in indexes:
                OneTimeJobMachine.objects.create(one_time_job=one_time_job, serial_number=s[index])
        cls.r1 = force_recurring_job(configuration=cls.c1, job=script)
        cls.r2 = force_recurring_job(configuration=cls.c2, job=mscp_check)
        cls.r3 = force_recurring_job(configuration=cls.c1, job=mscp_check)
        for recurring_job, indexes in ((cls.r1, (0, 1, 2, 3)), (cls.r2, (4, 5, 6, 7)), (cls.r3, (0, 6))):
            for index in indexes:
                RecurringJobMachine.objects.create(recurring_job=recurring_job, serial_number=s[index])

    def setUp(self):
        policies_cache.clear()

    # helpers

    def _machine(self, index):
        return f'Inventory::Machine::"{MetaMachine(self.serial_numbers[index]).get_urlsafe_serial_number()}"'

    def _atoms(self, schedule, kind, job, row_type, row, other_schedule):
        """The conditions of the policies: the six of the generated sets first, then the others."""
        core = {
            "all": "true",
            "machine": f"resource in {self._machine(6)}",
            "meta business unit": f'resource in Inventory::MetaBusinessUnit::"{self.mbu_a.pk}"',
            "configuration": f'resource in Turbo::Configuration::"{self.c1.pk}"',
            "schedule": f'resource in {schedule}',
            "kind": f'resource.job.kind == "{kind}"',
        }
        others = {
            "machine without a snapshot": f"resource in {self._machine(3)}",
            "other meta business unit": f'resource in Inventory::MetaBusinessUnit::"{self.mbu_c.pk}"',
            "job": f'resource.job == Turbo::Job::"{job.pk}"',
            "row ==": f'resource == {row_type}::"{row.pk}"',
            "row in": f'resource in {row_type}::"{row.pk}"',
            "not an ancestor": f'resource in {other_schedule}',
            "the job is not a parent": f'resource in Turbo::Job::"{job.pk}"',
            "upper case uuid": f'resource in Turbo::Configuration::"{str(self.c1.pk).upper()}"',
            "leading zero": f'resource in Inventory::MetaBusinessUnit::"0{self.mbu_a.pk}"',
            "machine with a nul": 'resource in Inventory::Machine::".AA"',
            "kind with a nul": f'resource.job.kind == "{kind}\\0"',
            "is": f"resource is {row_type}",
            "is another type": "resource is Turbo::JobUpload",
            "is another type and outside the subset": 'resource is Turbo::JobUpload && resource.artifact == "archive"',
            "is in": f'resource is {row_type} in Turbo::Configuration::"{self.c2.pk}"',
            "set": f'resource in [Inventory::MetaBusinessUnit::"{self.mbu_b.pk}", '
                   f'Inventory::MetaBusinessUnit::"{self.mbu_c.pk}"]',
            "set with ids that no unit has": f'resource in [Inventory::MetaBusinessUnit::"0{self.mbu_a.pk}", '
                                             f'Inventory::MetaBusinessUnit::"{self.mbu_b.pk}"]',
            "set of machines": f'resource in [{self._machine(0)}, {self._machine(6)}, Inventory::Machine::".AA", '
                               f"{self._machine(3)}]",
            "set of rows": f'resource in [{row_type}::"{row.pk}", {row_type}::"0{row.pk}"]',
            "and": f'resource in Inventory::MetaBusinessUnit::"{self.mbu_b.pk}" && resource.job.kind != "{kind}"',
            "or": f'resource in Inventory::MetaBusinessUnit::"{self.mbu_a.pk}" '
                  f'|| resource in Turbo::Configuration::"{self.c2.pk}"',
            "not": f'!(resource in Turbo::Configuration::"{self.c2.pk}")',
        }
        return core, others

    def _policy_sets(self, request_class, atoms, others):
        action = request_class.pbac_action
        permit = f'permit (principal in Role::"{self.group.pk}", action == {action}, resource)'
        forbid = f"forbid (principal, action == {action}, resource)"
        for permit_atom in atoms.values():
            for permit_kind in WHEN_UNLESS:
                yield f"{permit} {permit_kind} {{ {permit_atom} }};"
                for forbid_atom in atoms.values():
                    for forbid_kind in WHEN_UNLESS:
                        yield (f"{permit} {permit_kind} {{ {permit_atom} }};\n"
                               f"{forbid} {forbid_kind} {{ {forbid_atom} }};")
        for atom in others.values():
            for kind in WHEN_UNLESS:
                yield f"{permit} {kind} {{ {atom} }};"
                yield f"{permit};\n{forbid} {kind} {{ {atom} }};"
        # the scope form, with and without a type
        row_type = request_class.resource_type.qualified_name
        for atom in atoms.values():
            if atom.startswith("resource in "):
                for scope in (atom, atom.replace("resource in ", f"resource is {row_type} in ", 1)):
                    yield f'permit (principal in Role::"{self.group.pk}", action == {action}, {scope});'
                    yield f"{permit};\nforbid (principal, action == {action}, {scope});"
        # a policy of another action
        yield 'permit (principal, action == Turbo::Action::"viewJobUpload", resource);'

    def _set_policies(self, source):
        Policy.objects.filter(name="Tests").delete()
        Policy.objects.create(name="Tests", source=format_policies(source))
        policies_cache.clear()

    def _authorized_rows(self, request_class, rows):
        rows = list(rows)
        requests = request_class.requests_for_rows(self.user, rows)
        engine.authorize_requests(requests)
        return [row for row, request in zip(rows, requests) if request.is_authorized]

    def _rows(self, request_class, model):
        all_rows = {row.pk for row in model.objects.all()}
        expected = {row.pk for row in self._authorized_rows(request_class, model.objects.all())}
        scoped = scope_queryset(self.user, request_class.pbac_action, model.objects.all(), request_class.sql_map)
        self.assertIsNotNone(scoped)
        return all_rows, expected, set(scoped.values_list("pk", flat=True))

    def _assert_same_rows(self, request_class, model, atoms, others):
        count = 0
        for source in self._policy_sets(request_class, atoms, others):
            with self.subTest(source=source):
                self._set_policies(source)
                _, expected, scoped = self._rows(request_class, model)
                self.assertEqual(scoped, expected)
            count += 1
        return count

    def _assert_atoms(self, request_class, model, atoms, others):
        for name, atom in {**atoms, **others}.items():
            with self.subTest(atom=atom):
                source = (f'permit (principal in Role::"{self.group.pk}", action == {request_class.pbac_action}, '
                          f"resource) when {{ {atom} }};")
                # the policy form accepts it
                Policy(name=get_random_string(12), source=format_policies(source)).full_clean()
                if name in atoms and name != "all":
                    # some rows and not all, else the comparison proves little
                    self._set_policies(source)
                    all_rows, expected, _ = self._rows(request_class, model)
                    self.assertTrue(0 < len(expected) < len(all_rows))

    # one-time jobs

    def _one_time_atoms(self):
        row = OneTimeJobMachine.objects.get(one_time_job=self.o1, serial_number=self.serial_numbers[0])
        return self._atoms(f'Turbo::OneTimeJob::"{self.o2.pk}"', "file_export", self.o3.job,
                           "Turbo::OneTimeJobMachine", row, f'Turbo::RecurringJob::"{self.r1.pk}"')

    def test_one_time_job_machines(self):
        atoms, others = self._one_time_atoms()
        count = self._assert_same_rows(ViewOneTimeJobMachineRequest, OneTimeJobMachine, atoms, others)
        self.assertEqual(count, 6 * 2 * (1 + 6 * 2) + len(others) * 4 + 4 * 2 * 2 + 1)

    def test_one_time_job_machine_atoms(self):
        self._assert_atoms(ViewOneTimeJobMachineRequest, OneTimeJobMachine, *self._one_time_atoms())

    # recurring jobs

    def _recurring_atoms(self):
        row = RecurringJobMachine.objects.get(recurring_job=self.r3, serial_number=self.serial_numbers[0])
        return self._atoms(f'Turbo::RecurringJob::"{self.r1.pk}"', "mscp_check", self.r2.job,
                           "Turbo::RecurringJobMachine", row, f'Turbo::OneTimeJob::"{self.o1.pk}"')

    def test_recurring_job_machines(self):
        self._assert_same_rows(ViewRecurringJobMachineRequest, RecurringJobMachine, *self._recurring_atoms())

    def test_recurring_job_machine_atoms(self):
        self._assert_atoms(ViewRecurringJobMachineRequest, RecurringJobMachine, *self._recurring_atoms())

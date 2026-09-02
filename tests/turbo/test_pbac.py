from django.contrib.auth.models import Group
from django.core.exceptions import PermissionDenied
from django.test import TestCase
from django.utils.crypto import get_random_string

from accounts.models import Policy, User
from pbac.engine import engine
from zentral.contrib.inventory.models import MetaBusinessUnit, MetaMachine
from zentral.contrib.turbo.command_backends import CommandBackend
from zentral.contrib.turbo.models import ScheduleMode
from zentral.contrib.turbo.pbac import ScheduleCommandRequest, check_schedule_command

from .utils import force_command, force_script


class TurboPBACTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))

    def _set_policy(self, condition=None):
        source = ("permit ("
                  f' principal in Role::"{self.group.pk}",'
                  ' action == Turbo::Action::"scheduleCommand",'
                  " resource"
                  ")")
        if condition:
            source += f" when {{ {condition} }}"
        Policy.objects.update_or_create(name="Turbo tests", defaults={"source": source + ";\n"})

    # the request

    def test_machine_request_shape(self):
        command = force_command(backend=CommandBackend.FILE_EXPORT)
        machine = MetaMachine(get_random_string(12))
        request = ScheduleCommandRequest(self.user, command, ScheduleMode.ONE_TIME, machine)
        self.assertEqual(str(request.action), 'Turbo::Action::"scheduleCommand"')
        # the machine resource comes from inventory, so its MBU parents scope the collection
        self.assertEqual(request.resource.full_type, "Inventory::Machine")
        self.assertEqual(request.resource.id, machine.serial_number)
        self.assertEqual(request.context, {"backend": "file_export", "mode": "one_time"})

    def test_configuration_request_has_no_machine(self):
        # the configuration-page flow targets a scope expression, so there is no machine to name — the
        # kind is still policeable, which is why this action is an additional gate and not a replacement
        # for turbo.add_onetimejob
        command = force_command()
        request = ScheduleCommandRequest(self.user, command, ScheduleMode.ONE_TIME)
        self.assertEqual(request.resource.full_type, "System")
        self.assertEqual(request.resource.id, "any")
        self.assertEqual(request.context, {"backend": "sysdiagnose", "mode": "one_time"})

    # authorization

    def test_denied_by_default(self):
        command = force_command()
        request = ScheduleCommandRequest(self.user, command, ScheduleMode.ONE_TIME,
                                         MetaMachine(get_random_string(12)))
        engine.authorize_request(request)
        self.assertFalse(request.is_authorized)

    def test_authorized_by_an_unconditional_policy(self):
        self._set_policy()
        command = force_command()
        request = ScheduleCommandRequest(self.user, command, ScheduleMode.ONE_TIME,
                                         MetaMachine(get_random_string(12)))
        engine.authorize_request(request)
        self.assertTrue(request.is_authorized)

    def test_policy_can_allow_one_kind_and_refuse_another(self):
        # the point of the whole exercise: one turbo.add_onetimejob covers "collect a sysdiagnose" and
        # "glob arbitrary files off a laptop" identically, and this does not
        self._set_policy('context.backend == "sysdiagnose"')
        machine = MetaMachine(get_random_string(12))
        allowed = ScheduleCommandRequest(self.user, force_command(backend=CommandBackend.SYSDIAGNOSE),
                                         ScheduleMode.ONE_TIME, machine)
        engine.authorize_request(allowed)
        self.assertTrue(allowed.is_authorized)
        refused = ScheduleCommandRequest(self.user, force_command(backend=CommandBackend.FILE_EXPORT),
                                         ScheduleMode.ONE_TIME, machine)
        engine.authorize_request(refused)
        self.assertFalse(refused.is_authorized)

    def test_policy_can_scope_by_mode(self):
        # "one_time" on every request today, since allowed_modes keeps a command off a recurring
        # schedule — the attribute is what would make "no recurring collection" policy rather than code
        self._set_policy('context.mode == "one_time"')
        request = ScheduleCommandRequest(self.user, force_command(), ScheduleMode.ONE_TIME,
                                         MetaMachine(get_random_string(12)))
        engine.authorize_request(request)
        self.assertTrue(request.is_authorized)

    # the view helper

    class _FakeRequest:
        def __init__(self, user):
            self.user = user

    def test_check_is_a_noop_for_a_script(self):
        # only a command kind carries a backend worth policing; gating the others here would change
        # authorization for every shipped deployment
        script = force_script()
        check_schedule_command(self._FakeRequest(self.user), script.job, ScheduleMode.ONE_TIME)

    def test_check_raises_for_an_unauthorized_command(self):
        command = force_command()
        with self.assertRaises(PermissionDenied):
            check_schedule_command(self._FakeRequest(self.user), command.job, ScheduleMode.ONE_TIME)

    def test_check_passes_for_an_authorized_command(self):
        self._set_policy()
        command = force_command()
        check_schedule_command(self._FakeRequest(self.user), command.job, ScheduleMode.ONE_TIME)

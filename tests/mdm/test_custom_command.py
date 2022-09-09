import plistlib
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.commands import CustomCommand
from .utils import force_dep_enrollment_session


class CustomCommandTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()

    def test_load_kwargs(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        cmd_payload = {
            "RequestType": "InstalledApplicationList",
            "ManagedAppsOnly": False
        }
        cmd = CustomCommand.create_for_device(
            session.enrolled_device,
            kwargs={"command": plistlib.dumps(cmd_payload).decode("utf-8")},
            queue=True
        )
        self.assertEqual(cmd.command, {"ManagedAppsOnly": False})
        self.assertEqual(cmd.request_type, "InstalledApplicationList")

    def test_build_command(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        cmd_payload = {
            "RequestType": "InstalledApplicationList",
            "ManagedAppsOnly": False
        }
        cmd = CustomCommand.create_for_device(
            session.enrolled_device,
            kwargs={"command": plistlib.dumps(cmd_payload).decode("utf-8")},
            queue=True
        )
        self.assertEqual(cmd.build_command(), {"ManagedAppsOnly": False})

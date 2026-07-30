import glob
import json
import plistlib
import re
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.commands import CustomCommand, DeviceLock, EraseDevice, SetFirmwarePassword
from zentral.contrib.mdm.commands.base import AUDIT_OMITTED, AUDIT_REDACTED, registered_commands

from .utils import force_dep_enrollment_session


# Every kwarg the command classes write through the secret engine. The audit policy has to
# account for all of them, and test_no_encrypted_kwarg_is_missing_from_this_list keeps the
# list honest when a new command starts encrypting something.
ENCRYPTED_KWARGS = {"PIN", "new_password", "admin_password", "encryption_key"}

SENTINEL = "sentinel-must-never-be-serialized"


class CommandAuditTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.session, _, _ = force_dep_enrollment_session(cls.mbu, completed=True)
        cls.enrolled_device = cls.session.enrolled_device

    # the policy itself

    def test_no_encrypted_kwarg_is_missing_from_this_list(self):
        # get_secret_engine_kwargs() declares the encrypted field name in each command
        # module. Anything new there has to be classified, or it would be serialized
        # verbatim the moment somebody adds it to audit_public_kwargs.
        found = set()
        for path in glob.glob("zentral/contrib/mdm/commands/*.py"):
            found.update(re.findall(r"""field=["'](\w+)["']""", open(path).read()))
        self.assertEqual(found - ENCRYPTED_KWARGS, set())

    def test_encrypted_kwargs_are_never_public(self):
        for db_name, command_class in registered_commands.items():
            with self.subTest(db_name):
                self.assertEqual(set(command_class.audit_public_kwargs) & ENCRYPTED_KWARGS, set())

    def test_no_command_class_declares_a_kwarg_twice(self):
        for db_name, command_class in registered_commands.items():
            with self.subTest(db_name):
                self.assertEqual(
                    set(command_class.audit_public_kwargs) & set(command_class.audit_secret_kwargs),
                    set()
                )

    def test_undeclared_and_secret_kwargs_are_never_serialized(self):
        # Feed every command class a kwargs dict where each value is the sentinel, and
        # check the sentinel only ever survives under an explicitly public key.
        keys = ENCRYPTED_KWARGS | {"undeclared", "command"}
        for db_name, command_class in registered_commands.items():
            with self.subTest(db_name):
                kwargs = {key: SENTINEL for key in keys}
                audit_kwargs = command_class.build_audit_kwargs(kwargs)
                self.assertEqual(set(audit_kwargs), keys, "a kwarg went missing from the audit trail")
                for key, value in audit_kwargs.items():
                    if key in command_class.audit_public_kwargs:
                        continue
                    self.assertNotIn(SENTINEL, json.dumps(value))

    def test_secret_kwarg_is_redacted_and_undeclared_is_omitted(self):
        audit_kwargs = DeviceLock.build_audit_kwargs(
            {"Message": "lost", "PhoneNumber": "+123", "PIN": "encrypted", "surprise": "encrypted"}
        )
        self.assertEqual(
            audit_kwargs,
            {"Message": "lost",
             "PhoneNumber": "+123",
             "PIN": AUDIT_REDACTED,
             "surprise": AUDIT_OMITTED}
        )

    def test_erase_device_public_kwargs(self):
        self.assertEqual(
            EraseDevice.build_audit_kwargs(
                {"DisallowProximitySetup": True, "PreserveDataPlan": False, "PIN": "encrypted"}
            ),
            {"DisallowProximitySetup": True, "PreserveDataPlan": False, "PIN": AUDIT_REDACTED}
        )

    def test_set_firmware_password_has_no_public_kwargs(self):
        self.assertEqual(
            SetFirmwarePassword.build_audit_kwargs({"new_password": "encrypted"}),
            {"new_password": AUDIT_REDACTED}
        )

    # custom command, where the payload is operator supplied

    def test_custom_command_audit_kwargs_keep_shape_only(self):
        command = plistlib.dumps({"RequestType": "Settings",
                                 "Settings": [{"Item": "ApplicationAttributes"}],
                                  "Password": SENTINEL}).decode("utf-8")
        audit_kwargs = CustomCommand.build_audit_kwargs({"command": command})
        self.assertEqual(
            audit_kwargs,
            {"command": {"RequestType": "Settings", "keys": ["Password", "Settings"]}}
        )
        self.assertNotIn(SENTINEL, json.dumps(audit_kwargs))

    def test_custom_command_audit_kwargs_unparsable_payload(self):
        self.assertEqual(
            CustomCommand.build_audit_kwargs({"command": "not a property list"}),
            {"command": AUDIT_OMITTED}
        )

    def test_custom_command_audit_kwargs_no_request_type(self):
        command = plistlib.dumps({"Whatever": SENTINEL}).decode("utf-8")
        self.assertEqual(CustomCommand.build_audit_kwargs({"command": command}), {"command": AUDIT_OMITTED})

    # serialize_for_event, which is what the audit event carries

    def test_serialize_for_event_redacts_the_pin(self):
        command = DeviceLock.create_for_device(
            self.enrolled_device, kwargs={"Message": "lost", "PIN": "encrypted-pin"}, queue=True
        )
        serialized = command.db_command.serialize_for_event()
        self.assertEqual(serialized["kwargs"], {"Message": "lost", "PIN": AUDIT_REDACTED})
        self.assertNotIn("encrypted-pin", json.dumps(serialized))

    def test_serialize_for_event_without_kwargs_has_no_kwargs_key(self):
        command = DeviceLock.create_for_device(self.enrolled_device, queue=True)
        self.assertNotIn("kwargs", command.db_command.serialize_for_event())

    def test_serialize_for_event_unknown_command_name_omits_everything(self):
        command = DeviceLock.create_for_device(
            self.enrolled_device, kwargs={"Message": "lost"}, queue=True
        )
        db_command = command.db_command
        db_command.name = "NotARegisteredCommand"
        db_command.save()
        self.assertEqual(db_command.serialize_for_event()["kwargs"], {"Message": AUDIT_OMITTED})

from django.contrib.auth.models import Group
from django.test import TestCase
from django.utils.crypto import get_random_string

from accounts.models import Policy, User
from pbac.engine import engine
from zentral.contrib.inventory.models import MachineSnapshotCommit, MetaBusinessUnit, MetaMachine
from zentral.contrib.mdm.models import Channel
from zentral.contrib.mdm.pbac import (
    BlockEnrolledDeviceRequest,
    ForceInstallArtifactRequest,
    UnblockEnrolledDeviceRequest,
)

from .utils import force_artifact


class MDMPBACTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        cls.artifact, _ = force_artifact()

    def _build_request(self, channel=Channel.DEVICE, user=None):
        machine = MetaMachine(get_random_string(12))
        return ForceInstallArtifactRequest(user or self.user, machine, self.artifact, channel), machine

    def _set_policy(self, condition=None):
        source = ("permit ("
                  f' principal in Role::"{self.group.pk}",'
                  ' action == MDM::Action::"forceInstallArtifact",'
                  " resource"
                  ")")
        if condition:
            source += f" when {{ {condition} }}"
        Policy.objects.update_or_create(name="MDM tests", defaults={"source": source + ";\n"})

    def test_force_install_artifact_request(self):
        request, machine = self._build_request(channel=Channel.USER)
        self.assertEqual(str(request.action), 'MDM::Action::"forceInstallArtifact"')
        self.assertEqual(request.resource.full_type, "Inventory::Machine")
        self.assertEqual(request.resource.id, machine.serial_number)
        self.assertEqual(
            request.context,
            {"artifactType": "Profile",
             "artifactID": str(self.artifact.pk),
             "artifactName": self.artifact.name,
             "channel": "User"}
        )

    def test_force_install_artifact_request_denied_by_default(self):
        request, _ = self._build_request()
        engine.authorize_request(request)
        self.assertFalse(request.is_authorized)

    def test_force_install_artifact_request_superuser_authorized(self):
        superuser = User.objects.create_user(
            get_random_string(12), "superuser@zentral.io", get_random_string(12),
            is_superuser=True,
        )
        request, _ = self._build_request(user=superuser)
        self.assertTrue(request.is_authorized)

    def test_force_install_artifact_request_policy_authorized(self):
        self._set_policy()
        request, _ = self._build_request()
        engine.authorize_request(request)
        self.assertTrue(request.is_authorized)

    def test_force_install_artifact_request_policy_context_authorized(self):
        self._set_policy(f'context.artifactType == "Profile" && context.artifactID == "{self.artifact.pk}"')
        request, _ = self._build_request()
        engine.authorize_request(request)
        self.assertTrue(request.is_authorized)

    def test_force_install_artifact_request_policy_context_denied(self):
        self._set_policy('context.artifactType == "Store App"')
        request, _ = self._build_request()
        engine.authorize_request(request)
        self.assertFalse(request.is_authorized)

    # block & unblock

    def _set_block_state_policy(self, action_id, mbu=None):
        resource = f'resource in Inventory::MetaBusinessUnit::"{mbu.pk}"' if mbu else "resource"
        Policy.objects.update_or_create(
            name="MDM tests",
            defaults={"source": ("permit ("
                                 f' principal in Role::"{self.group.pk}",'
                                 f' action == MDM::Action::"{action_id}",'
                                 f" {resource}"
                                 ");\n")},
        )

    def _force_machine_in_mbu(self, mbu):
        serial_number = get_random_string(12)
        MachineSnapshotCommit.objects.commit_machine_snapshot_tree({
            "source": {"module": "zentral.contrib.mdm", "name": "MDM"},
            "business_unit": mbu.create_enrollment_business_unit().serialize(),
            "serial_number": serial_number,
        })
        return MetaMachine(serial_number)

    def test_block_enrolled_device_request(self):
        machine = MetaMachine(get_random_string(12))
        request = BlockEnrolledDeviceRequest(self.user, machine)
        self.assertEqual(str(request.action), 'MDM::Action::"blockEnrolledDevice"')
        self.assertEqual(request.resource.full_type, "Inventory::Machine")
        self.assertEqual(request.resource.id, machine.serial_number)
        self.assertEqual(request.context, {})

    def test_unblock_enrolled_device_request(self):
        machine = MetaMachine(get_random_string(12))
        request = UnblockEnrolledDeviceRequest(self.user, machine)
        self.assertEqual(str(request.action), 'MDM::Action::"unblockEnrolledDevice"')
        self.assertEqual(request.resource.full_type, "Inventory::Machine")
        self.assertEqual(request.resource.id, machine.serial_number)
        self.assertEqual(request.context, {})

    def test_block_enrolled_device_request_denied_by_default(self):
        request = BlockEnrolledDeviceRequest(self.user, MetaMachine(get_random_string(12)))
        engine.authorize_request(request)
        self.assertFalse(request.is_authorized)

    def test_unblock_enrolled_device_request_denied_by_default(self):
        request = UnblockEnrolledDeviceRequest(self.user, MetaMachine(get_random_string(12)))
        engine.authorize_request(request)
        self.assertFalse(request.is_authorized)

    def test_block_policy_does_not_authorize_unblock(self):
        self._set_block_state_policy("blockEnrolledDevice")
        machine = MetaMachine(get_random_string(12))
        block_request = BlockEnrolledDeviceRequest(self.user, machine)
        unblock_request = UnblockEnrolledDeviceRequest(self.user, machine)
        engine.authorize_requests([block_request, unblock_request])
        self.assertTrue(block_request.is_authorized)
        self.assertFalse(unblock_request.is_authorized)

    def test_unblock_policy_does_not_authorize_block(self):
        self._set_block_state_policy("unblockEnrolledDevice")
        machine = MetaMachine(get_random_string(12))
        block_request = BlockEnrolledDeviceRequest(self.user, machine)
        unblock_request = UnblockEnrolledDeviceRequest(self.user, machine)
        engine.authorize_requests([block_request, unblock_request])
        self.assertFalse(block_request.is_authorized)
        self.assertTrue(unblock_request.is_authorized)

    def test_block_enrolled_device_request_mbu_policy_authorized(self):
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        self._set_block_state_policy("blockEnrolledDevice", mbu=mbu)
        request = BlockEnrolledDeviceRequest(self.user, self._force_machine_in_mbu(mbu))
        engine.authorize_request(request)
        self.assertTrue(request.is_authorized)

    def test_block_enrolled_device_request_mbu_policy_denied(self):
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        other_mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        self._set_block_state_policy("blockEnrolledDevice", mbu=mbu)
        request = BlockEnrolledDeviceRequest(self.user, self._force_machine_in_mbu(other_mbu))
        engine.authorize_request(request)
        self.assertFalse(request.is_authorized)

    def test_unblock_enrolled_device_request_mbu_policy_authorized(self):
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        self._set_block_state_policy("unblockEnrolledDevice", mbu=mbu)
        request = UnblockEnrolledDeviceRequest(self.user, self._force_machine_in_mbu(mbu))
        engine.authorize_request(request)
        self.assertTrue(request.is_authorized)

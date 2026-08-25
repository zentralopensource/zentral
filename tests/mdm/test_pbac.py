from django.contrib.auth.models import Group
from django.test import TestCase
from django.utils.crypto import get_random_string

from accounts.models import Policy, User
from pbac.engine import engine
from zentral.contrib.inventory.models import MetaMachine
from zentral.contrib.mdm.models import Channel
from zentral.contrib.mdm.pbac import ForceInstallArtifactRequest

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

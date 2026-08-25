import uuid
from unittest.mock import patch

from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import APIToken, Policy, User
from tests.zentral_test_utils.request_case import RequestCase
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.models import Channel, DeviceArtifact, TargetArtifact, UserArtifact
from zentral.utils.time import naive_utcnow

from .utils import (
    force_blueprint,
    force_blueprint_artifact,
    force_enrolled_user,
    force_user_enrollment_session,
)


class APITargetArtifactsViewsTestCase(TestCase, RequestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True
        )
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        _, cls.api_key = APIToken.objects.create_for_user(cls.service_account)
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        session, _, _ = force_user_enrollment_session(cls.mbu, completed=True)
        cls.enrolled_device = session.enrolled_device
        cls.enrolled_device.platform = "macOS"
        cls.enrolled_device.blueprint = force_blueprint()
        cls.enrolled_device.save()
        cls.enrolled_user = force_enrolled_user(cls.enrolled_device)

    # RequestCase implementation

    def _get_api_key(self):
        return self.api_key

    # utils

    def set_permissions(self, *permissions):
        source = "\n".join(
            "permit ("
            f' principal in Role::"{self.group.pk}",'
            f' action == {action},'
            " resource"
            ");"
            for action in permissions
        )
        Policy.objects.update_or_create(name="Tests", defaults={"source": source})

    def _force_target_artifact(self, enrolled_user=None, **kwargs):
        _, artifact, (artifact_version,) = force_blueprint_artifact(
            blueprint=self.enrolled_device.blueprint,
            channel=Channel.USER if enrolled_user else Channel.DEVICE,
        )
        defaults = {"artifact_version": artifact_version,
                    "status": TargetArtifact.Status.INSTALLED}
        defaults.update(kwargs)
        if enrolled_user:
            target_artifact = UserArtifact.objects.create(enrolled_user=enrolled_user, **defaults)
        else:
            target_artifact = DeviceArtifact.objects.create(enrolled_device=self.enrolled_device, **defaults)
        return artifact, artifact_version, target_artifact

    # list enrolled device artifacts

    def test_enrolled_device_artifacts_unauthorized(self):
        response = self.get(reverse("mdm_api:enrolled_device_artifacts"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_enrolled_device_artifacts_permission_denied(self):
        response = self.get(reverse("mdm_api:enrolled_device_artifacts"))
        self.assertEqual(response.status_code, 403)

    def test_enrolled_device_artifacts_unknown_device_filter(self):
        self.set_permissions('MDM::Action::"viewDeviceArtifact"')
        response = self.get(reverse("mdm_api:enrolled_device_artifacts"),
                            data={"enrolled_device": self.enrolled_device.pk + 100})
        self.assertEqual(response.status_code, 400)

    def test_enrolled_device_artifacts(self):
        artifact, artifact_version, target_artifact = self._force_target_artifact()
        other_session, _, _ = force_user_enrollment_session(self.mbu, completed=True)
        DeviceArtifact.objects.create(
            enrolled_device=other_session.enrolled_device,
            artifact_version=artifact_version,
            status=TargetArtifact.Status.FAILED,
        )
        self.set_permissions('MDM::Action::"viewDeviceArtifact"')
        # without a device filter, the target artifacts of all the devices are listed
        response = self.get(reverse("mdm_api:enrolled_device_artifacts"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 2)
        # with the device filter, only the target artifacts of the device are listed
        response = self.get(reverse("mdm_api:enrolled_device_artifacts"),
                            data={"enrolled_device": self.enrolled_device.pk})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["count"], 1)
        self.assertEqual(
            payload["results"],
            [{"id": target_artifact.pk,
              "enrolled_device": self.enrolled_device.pk,
              "artifact": str(artifact.pk),
              "artifact_version": str(artifact_version.pk),
              "version": 1,
              "status": "Installed",
              "extra_info": {},
              "installed_at": None,
              "os_version_at_install_time": None,
              "unique_install_identifier": "",
              "install_count": 0,
              "retry_count": 0,
              "max_retry_count": 0,
              "force_install_requested_at": None,
              "created_at": target_artifact.created_at.isoformat(),
              "updated_at": target_artifact.updated_at.isoformat()}]
        )

    def test_enrolled_device_artifacts_filters(self):
        artifact, _, target_artifact = self._force_target_artifact(
            status=TargetArtifact.Status.FAILED,
            force_install_requested_at=naive_utcnow(),
        )
        _, _, other_target_artifact = self._force_target_artifact()
        self.set_permissions('MDM::Action::"viewDeviceArtifact"')
        url = reverse("mdm_api:enrolled_device_artifacts")
        # artifact filter
        response = self.get(url, data={"artifact": str(artifact.pk)})
        self.assertEqual(response.status_code, 200)
        self.assertEqual([r["id"] for r in response.json()["results"]], [target_artifact.pk])
        # status filter
        response = self.get(url, data={"status": "Failed"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual([r["id"] for r in response.json()["results"]], [target_artifact.pk])
        # force install requested filter
        response = self.get(url, data={"force_install_requested": "true"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual([r["id"] for r in response.json()["results"]], [target_artifact.pk])
        response = self.get(url, data={"force_install_requested": "false"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual([r["id"] for r in response.json()["results"]], [other_target_artifact.pk])

    # list enrolled user artifacts

    def test_enrolled_user_artifacts_unauthorized(self):
        response = self.get(reverse("mdm_api:enrolled_user_artifacts"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_enrolled_user_artifacts_permission_denied(self):
        response = self.get(reverse("mdm_api:enrolled_user_artifacts"))
        self.assertEqual(response.status_code, 403)

    def test_enrolled_user_artifacts(self):
        artifact, artifact_version, target_artifact = self._force_target_artifact(self.enrolled_user)
        other_enrolled_user = force_enrolled_user(self.enrolled_device)
        UserArtifact.objects.create(
            enrolled_user=other_enrolled_user,
            artifact_version=artifact_version,
            status=TargetArtifact.Status.FAILED,
        )
        self.set_permissions('MDM::Action::"viewUserArtifact"')
        # without a user filter, the target artifacts of all the users are listed
        response = self.get(reverse("mdm_api:enrolled_user_artifacts"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 2)
        # with the user filter, only the target artifacts of the user are listed
        response = self.get(reverse("mdm_api:enrolled_user_artifacts"),
                            data={"enrolled_user": self.enrolled_user.pk})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["count"], 1)
        result = payload["results"][0]
        self.assertEqual(result["id"], target_artifact.pk)
        self.assertEqual(result["enrolled_user"], self.enrolled_user.pk)
        self.assertEqual(result["artifact"], str(artifact.pk))

    # force install enrolled device artifact

    def test_force_install_enrolled_device_artifact_unauthorized(self):
        artifact, _, _ = self._force_target_artifact()
        response = self.post(
            reverse("mdm_api:force_install_enrolled_device_artifact",
                    args=(self.enrolled_device.pk, artifact.pk)),
            include_token=False,
        )
        self.assertEqual(response.status_code, 401)

    def test_force_install_enrolled_device_artifact_permission_denied(self):
        artifact, _, _ = self._force_target_artifact()
        response = self.post(
            reverse("mdm_api:force_install_enrolled_device_artifact",
                    args=(self.enrolled_device.pk, artifact.pk)),
        )
        self.assertEqual(response.status_code, 403)

    def test_force_install_enrolled_device_artifact_unknown_device(self):
        artifact, _, _ = self._force_target_artifact()
        self.set_permissions('MDM::Action::"forceInstallArtifact"')
        response = self.post(
            reverse("mdm_api:force_install_enrolled_device_artifact",
                    args=(self.enrolled_device.pk + 100, artifact.pk)),
        )
        self.assertEqual(response.status_code, 404)

    def test_force_install_enrolled_device_artifact_unknown_artifact(self):
        self._force_target_artifact()
        self.set_permissions('MDM::Action::"forceInstallArtifact"')
        response = self.post(
            reverse("mdm_api:force_install_enrolled_device_artifact",
                    args=(self.enrolled_device.pk, uuid.uuid4())),
        )
        self.assertEqual(response.status_code, 404)

    def test_force_install_enrolled_device_artifact_error(self):
        artifact, _, _ = self._force_target_artifact()
        DeviceArtifact.objects.all().delete()
        self.set_permissions('MDM::Action::"forceInstallArtifact"')
        response = self.post(
            reverse("mdm_api:force_install_enrolled_device_artifact",
                    args=(self.enrolled_device.pk, artifact.pk)),
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {"detail": "No install attempted yet for the artifact version in scope. "
                       "It will be installed at the next connection."}
        )

    @patch("zentral.contrib.mdm.api_views.target_artifacts.send_enrolled_device_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_force_install_enrolled_device_artifact(self, post_event, send_enrolled_device_notification):
        artifact, artifact_version, target_artifact = self._force_target_artifact()
        stale_command = self.enrolled_device.commands.create(
            uuid=uuid.uuid4(),
            name="InstalledApplicationList",
            artifact_version=artifact_version,
        )
        self.set_permissions('MDM::Action::"forceInstallArtifact"')
        with self.captureOnCommitCallbacks(execute=True):
            response = self.post(
                reverse("mdm_api:force_install_enrolled_device_artifact",
                        args=(self.enrolled_device.pk, artifact.pk)),
            )
        self.assertEqual(response.status_code, 200)
        target_artifact.refresh_from_db()
        payload = response.json()
        self.assertEqual(payload["deleted_command_count"], 1)
        self.assertEqual(payload["target_artifact"]["id"], target_artifact.pk)
        self.assertEqual(payload["target_artifact"]["retry_count"], 1)
        self.assertEqual(payload["target_artifact"]["max_retry_count"], 3)
        self.assertEqual(payload["target_artifact"]["force_install_requested_at"],
                         target_artifact.force_install_requested_at.isoformat())
        self.assertEqual(self.enrolled_device.commands.filter(pk=stale_command.pk).count(), 0)
        send_enrolled_device_notification.assert_called_once()
        self.assertEqual(send_enrolled_device_notification.call_args.args[0], self.enrolled_device)
        event = post_event.call_args_list[-1].args[0]
        self.assertEqual(event.payload["result"], "updated")
        self.assertEqual(event.payload["target_artifact"]["retries_exhausted"], False)
        self.assertTrue(event.metadata.request.user.session["token_authenticated"])
        self.assertEqual(event.metadata.machine_serial_number, self.enrolled_device.serial_number)

    # force install enrolled user artifact

    def test_force_install_enrolled_user_artifact_permission_denied(self):
        artifact, _, _ = self._force_target_artifact(self.enrolled_user)
        response = self.post(
            reverse("mdm_api:force_install_enrolled_user_artifact",
                    args=(self.enrolled_user.pk, artifact.pk)),
        )
        self.assertEqual(response.status_code, 403)

    def test_force_install_enrolled_user_artifact_unknown_user(self):
        artifact, _, _ = self._force_target_artifact(self.enrolled_user)
        self.set_permissions('MDM::Action::"forceInstallArtifact"')
        response = self.post(
            reverse("mdm_api:force_install_enrolled_user_artifact",
                    args=(self.enrolled_user.pk + 100, artifact.pk)),
        )
        self.assertEqual(response.status_code, 404)

    @patch("zentral.contrib.mdm.api_views.target_artifacts.send_enrolled_user_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_force_install_enrolled_user_artifact(self, post_event, send_enrolled_user_notification):
        artifact, _, target_artifact = self._force_target_artifact(self.enrolled_user)
        self.set_permissions('MDM::Action::"forceInstallArtifact"')
        with self.captureOnCommitCallbacks(execute=True):
            response = self.post(
                reverse("mdm_api:force_install_enrolled_user_artifact",
                        args=(self.enrolled_user.pk, artifact.pk)),
            )
        self.assertEqual(response.status_code, 200)
        target_artifact.refresh_from_db()
        payload = response.json()
        self.assertEqual(payload["deleted_command_count"], 0)
        self.assertEqual(payload["target_artifact"]["id"], target_artifact.pk)
        self.assertEqual(payload["target_artifact"]["enrolled_user"], self.enrolled_user.pk)
        self.assertIsNotNone(target_artifact.force_install_requested_at)
        send_enrolled_user_notification.assert_called_once()
        self.assertEqual(send_enrolled_user_notification.call_args.args[0], self.enrolled_user)
        event = post_event.call_args_list[-1].args[0]
        self.assertEqual(event.payload["channel"], "User")

import uuid
from unittest.mock import patch

from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import Policy, User
from tests.zentral_test_utils.login_case import LoginCase
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.models import Channel, DeviceArtifact, TargetArtifact, UserArtifact, UserCommand
from zentral.utils.time import naive_utcnow

from .utils import (
    force_blueprint,
    force_blueprint_artifact,
    force_enrolled_user,
    force_user_enrollment_session,
)


class MDMForceInstallViewsTestCase(TestCase, LoginCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "mdm"

    # utils

    def _set_policy(self, condition=None):
        source = ("permit ("
                  f' principal in Role::"{self.group.pk}",'
                  ' action == MDM::Action::"forceInstallArtifact",'
                  " resource"
                  ")")
        if condition:
            source += f" when {{ {condition} }}"
        Policy.objects.update_or_create(name="MDM tests", defaults={"source": source + ";\n"})

    def _force_enrolled_device(self):
        session, _, _ = force_user_enrollment_session(self.mbu, completed=True)
        enrolled_device = session.enrolled_device
        enrolled_device.platform = "macOS"
        enrolled_device.blueprint = force_blueprint()
        enrolled_device.save()
        return enrolled_device

    def _force_target_artifact(self, enrolled_device, enrolled_user=None, **kwargs):
        _, artifact, (artifact_version,) = force_blueprint_artifact(
            blueprint=enrolled_device.blueprint,
            channel=Channel.USER if enrolled_user else Channel.DEVICE,
        )
        defaults = {"artifact_version": artifact_version,
                    "status": TargetArtifact.Status.INSTALLED}
        defaults.update(kwargs)
        if enrolled_user:
            target_artifact = UserArtifact.objects.create(enrolled_user=enrolled_user, **defaults)
        else:
            target_artifact = DeviceArtifact.objects.create(enrolled_device=enrolled_device, **defaults)
        return artifact, artifact_version, target_artifact

    def device_url(self, enrolled_device, artifact):
        return reverse("mdm:force_install_device_artifact", args=(enrolled_device.pk, artifact.pk))

    def user_url(self, enrolled_user, artifact):
        return reverse("mdm:force_install_user_artifact",
                       args=(enrolled_user.enrolled_device.pk, enrolled_user.pk, artifact.pk))

    # device page force install buttons

    def test_enrolled_device_no_force_install_button_without_policy(self):
        enrolled_device = self._force_enrolled_device()
        artifact, _, _ = self._force_target_artifact(enrolled_device)
        self.login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_device", args=(enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, artifact.name)
        self.assertNotContains(response, "Force install")

    def test_enrolled_device_force_install_button(self):
        enrolled_device = self._force_enrolled_device()
        artifact, _, _ = self._force_target_artifact(enrolled_device)
        self.login("mdm.view_enrolleddevice")
        self._set_policy()
        response = self.client.get(reverse("mdm:enrolled_device", args=(enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Force install")
        self.assertContains(response, self.device_url(enrolled_device, artifact))

    def test_enrolled_device_no_force_install_button_blocked_device(self):
        enrolled_device = self._force_enrolled_device()
        self._force_target_artifact(enrolled_device)
        enrolled_device.blocked_at = naive_utcnow()
        enrolled_device.save()
        self.login("mdm.view_enrolleddevice")
        self._set_policy()
        response = self.client.get(reverse("mdm:enrolled_device", args=(enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Force install")

    def test_enrolled_device_no_force_install_button_stale_artifact_version(self):
        enrolled_device = self._force_enrolled_device()
        _, artifact, (artifact_version, previous_artifact_version) = force_blueprint_artifact(
            blueprint=enrolled_device.blueprint,
            version_count=2,
        )
        DeviceArtifact.objects.create(
            enrolled_device=enrolled_device,
            artifact_version=previous_artifact_version,
            status=TargetArtifact.Status.INSTALLED,
        )
        self.login("mdm.view_enrolleddevice")
        self._set_policy()
        response = self.client.get(reverse("mdm:enrolled_device", args=(enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, artifact.name)
        self.assertNotContains(response, "Force install")

    def test_enrolled_device_force_install_requested_badge(self):
        enrolled_device = self._force_enrolled_device()
        self._force_target_artifact(enrolled_device, force_install_requested_at=naive_utcnow())
        self.login("mdm.view_enrolleddevice")
        response = self.client.get(reverse("mdm:enrolled_device", args=(enrolled_device.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "install requested")

    def test_enrolled_user_force_install_button(self):
        enrolled_device = self._force_enrolled_device()
        enrolled_user = force_enrolled_user(enrolled_device)
        artifact, _, _ = self._force_target_artifact(enrolled_device, enrolled_user)
        self.login("mdm.view_enrolleduser")
        self._set_policy()
        response = self.client.get(
            reverse("mdm:enrolled_user", args=(enrolled_device.pk, enrolled_user.pk))
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Force install")
        self.assertContains(response, self.user_url(enrolled_user, artifact))

    # force install device artifact

    def test_force_install_device_artifact_redirect(self):
        enrolled_device = self._force_enrolled_device()
        artifact, _, _ = self._force_target_artifact(enrolled_device)
        self.login_redirect("force_install_device_artifact", enrolled_device.pk, artifact.pk)

    def test_force_install_device_artifact_permission_denied(self):
        enrolled_device = self._force_enrolled_device()
        artifact, _, _ = self._force_target_artifact(enrolled_device)
        self.login()
        response = self.client.get(self.device_url(enrolled_device, artifact))
        self.assertEqual(response.status_code, 403)

    def test_force_install_device_artifact_unknown_device(self):
        enrolled_device = self._force_enrolled_device()
        artifact, _, _ = self._force_target_artifact(enrolled_device)
        self.login()
        self._set_policy()
        response = self.client.get(
            reverse("mdm:force_install_device_artifact", args=(enrolled_device.pk + 100, artifact.pk))
        )
        self.assertEqual(response.status_code, 404)

    def test_force_install_device_artifact_unknown_artifact(self):
        enrolled_device = self._force_enrolled_device()
        self._force_target_artifact(enrolled_device)
        self.login()
        self._set_policy()
        response = self.client.get(
            reverse("mdm:force_install_device_artifact",
                    args=(enrolled_device.pk, "00000000-0000-0000-0000-000000000000"))
        )
        self.assertEqual(response.status_code, 404)

    def test_force_install_device_artifact_get(self):
        enrolled_device = self._force_enrolled_device()
        artifact, _, target_artifact = self._force_target_artifact(
            enrolled_device,
            force_install_requested_at=naive_utcnow(),
        )
        self.login()
        self._set_policy()
        response = self.client.get(self.device_url(enrolled_device, artifact))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/targetartifact_confirm_force_install.html")
        self.assertContains(response, artifact.name)
        self.assertContains(response, "Do you really want to force the install of this artifact?")
        self.assertContains(response, "Install requested")
        self.assertEqual(response.context["target_artifact"], target_artifact)

    def test_force_install_device_artifact_get_no_target_artifact(self):
        enrolled_device = self._force_enrolled_device()
        _, artifact, _ = force_blueprint_artifact(blueprint=enrolled_device.blueprint)
        self.login()
        self._set_policy()
        response = self.client.get(self.device_url(enrolled_device, artifact))
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.context["target_artifact"])
        self.assertNotContains(response, "Install count")

    @patch("zentral.contrib.mdm.views.management.send_enrolled_device_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_force_install_device_artifact_post(self, post_event, send_enrolled_device_notification):
        enrolled_device = self._force_enrolled_device()
        artifact, _, target_artifact = self._force_target_artifact(enrolled_device)
        self.login("mdm.view_enrolleddevice")
        self._set_policy(f'context.artifactID == "{artifact.pk}"')
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(self.device_url(enrolled_device, artifact), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, f"Installation of artifact {artifact} requested.")
        self.assertNotContains(response, "stale command")
        target_artifact.refresh_from_db()
        self.assertIsNotNone(target_artifact.force_install_requested_at)
        self.assertEqual(target_artifact.retry_count, 1)
        self.assertEqual(target_artifact.max_retry_count, 3)
        send_enrolled_device_notification.assert_called_once()
        self.assertEqual(send_enrolled_device_notification.call_args.args[0], enrolled_device)
        event = post_event.call_args_list[-1].args[0]
        self.assertEqual(event.payload["result"], "updated")
        self.assertEqual(event.payload["target_artifact"]["retries_exhausted"], False)
        self.assertEqual(event.metadata.request.user.username, self.user.username)
        self.assertEqual(event.metadata.machine_serial_number, enrolled_device.serial_number)

    @patch("zentral.contrib.mdm.views.management.send_enrolled_device_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_force_install_device_artifact_post_stale_command_deleted(
        self, post_event, send_enrolled_device_notification
    ):
        enrolled_device = self._force_enrolled_device()
        artifact, artifact_version, _ = self._force_target_artifact(enrolled_device)
        for _ in range(2):
            enrolled_device.commands.create(
                uuid=uuid.uuid4(),
                name="InstalledApplicationList",
                artifact_version=artifact_version,
            )
        self.login("mdm.view_enrolleddevice")
        self._set_policy()
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(self.device_url(enrolled_device, artifact), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "2 stale commands deleted.")
        self.assertEqual(enrolled_device.commands.count(), 0)

    @patch("zentral.contrib.mdm.views.management.send_enrolled_device_notification")
    def test_force_install_device_artifact_post_error(self, send_enrolled_device_notification):
        enrolled_device = self._force_enrolled_device()
        artifact, _, _ = self._force_target_artifact(enrolled_device)
        enrolled_device.blocked_at = naive_utcnow()
        enrolled_device.save()
        self.login("mdm.view_enrolleddevice")
        self._set_policy()
        response = self.client.post(self.device_url(enrolled_device, artifact), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleddevice_detail.html")
        self.assertContains(response, "Device blocked")
        send_enrolled_device_notification.assert_not_called()

    # force install user artifact

    def test_force_install_user_artifact_permission_denied(self):
        enrolled_device = self._force_enrolled_device()
        enrolled_user = force_enrolled_user(enrolled_device)
        artifact, _, _ = self._force_target_artifact(enrolled_device, enrolled_user)
        self.login()
        response = self.client.get(self.user_url(enrolled_user, artifact))
        self.assertEqual(response.status_code, 403)

    def test_force_install_user_artifact_unknown_user(self):
        enrolled_device = self._force_enrolled_device()
        enrolled_user = force_enrolled_user(enrolled_device)
        artifact, _, _ = self._force_target_artifact(enrolled_device, enrolled_user)
        self.login()
        self._set_policy()
        response = self.client.get(
            reverse("mdm:force_install_user_artifact",
                    args=(enrolled_device.pk, enrolled_user.pk + 100, artifact.pk))
        )
        self.assertEqual(response.status_code, 404)

    def test_force_install_user_artifact_get(self):
        enrolled_device = self._force_enrolled_device()
        enrolled_user = force_enrolled_user(enrolled_device)
        artifact, _, target_artifact = self._force_target_artifact(enrolled_device, enrolled_user)
        self.login()
        self._set_policy('context.channel == "User"')
        response = self.client.get(self.user_url(enrolled_user, artifact))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/targetartifact_confirm_force_install.html")
        self.assertEqual(response.context["target_artifact"], target_artifact)

    @patch("zentral.contrib.mdm.views.management.send_enrolled_user_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_force_install_user_artifact_post(self, post_event, send_enrolled_user_notification):
        enrolled_device = self._force_enrolled_device()
        enrolled_user = force_enrolled_user(enrolled_device)
        artifact, artifact_version, target_artifact = self._force_target_artifact(enrolled_device, enrolled_user)
        stale_command = UserCommand.objects.create(
            uuid=uuid.uuid4(),
            enrolled_user=enrolled_user,
            name="InstallProfile",
            artifact_version=artifact_version,
        )
        self.login("mdm.view_enrolleduser")
        self._set_policy()
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(self.user_url(enrolled_user, artifact), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enrolleduser_detail.html")
        self.assertContains(response, f"Installation of artifact {artifact} requested.")
        self.assertContains(response, "1 stale command deleted.")
        self.assertEqual(UserCommand.objects.filter(pk=stale_command.pk).count(), 0)
        target_artifact.refresh_from_db()
        self.assertIsNotNone(target_artifact.force_install_requested_at)
        send_enrolled_user_notification.assert_called_once()
        self.assertEqual(send_enrolled_user_notification.call_args.args[0], enrolled_user)
        event = post_event.call_args_list[-1].args[0]
        self.assertEqual(event.payload["channel"], "User")
        self.assertEqual(event.payload["enrolled_user"],
                         {"pk": enrolled_user.pk, "user_id": enrolled_user.user_id})

import json
import plistlib
from unittest.mock import patch

from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import User
from tests.zentral_test_utils.login_case import LoginCase
from zentral.contrib.mdm.models import Artifact, Channel, Platform
from zentral.core.events.base import AuditEvent

from .utils import force_artifact, force_blueprint, force_blueprint_artifact, force_location_asset


class ArtifactAuditEventTestCase(TestCase, LoginCase):
    """The artifact views deploy profiles and apps to every device in a blueprint, so each
    one has to leave an audit trail. The behaviour of the views themselves is covered by
    the per view test cases; this only checks that the event is emitted."""

    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "mdm"

    def assert_audit_event(self, post_event, callbacks, action, model, pk):
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(event.payload["action"], action)
        self.assertEqual(event.payload["object"]["model"], model)
        self.assertEqual(event.payload["object"]["pk"], str(pk))
        return event

    # artifacts

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_artifact_audit_event(self, post_event):
        # BaseCreateArtifactView, so every artifact creation form is covered
        data_asset_artifact, _ = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        self.login("mdm.add_artifact", "mdm.view_artifact")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:create_configuration"),
                                        {"source": json.dumps({
                                            "Identifier": get_random_string(12),
                                            "Type": "com.apple.configuration.services.configuration-files",
                                            "Payload": {
                                                "ServiceType": "com.apple.sudo",
                                                "DataAssetReference": f"ztl:{data_asset_artifact.pk}"
                                            },
                                         }),
                                         "name": get_random_string(12),
                                         "channel": str(Channel.DEVICE),
                                         "platforms": [str(Platform.MACOS)]},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        artifact = response.context["object"]
        self.assert_audit_event(post_event, callbacks, "created", "mdm.artifact", artifact.pk)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_artifact_audit_event(self, post_event):
        artifact, _ = force_artifact()
        prev_name = artifact.name
        new_name = get_random_string(12)
        self.login("mdm.change_artifact", "mdm.view_artifact")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:update_artifact", args=(artifact.pk,)),
                                        {"name": new_name,
                                         "platforms": [Platform.MACOS.value],
                                         "reinstall_interval": 0,
                                         "reinstall_on_os_update": Artifact.ReinstallOnOSUpdate.NO.value},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        event = self.assert_audit_event(post_event, callbacks, "updated", "mdm.artifact", artifact.pk)
        self.assertEqual(event.payload["object"]["prev_value"]["name"], prev_name)
        self.assertEqual(event.payload["object"]["new_value"]["name"], new_name)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_artifact_audit_event(self, post_event):
        artifact, _ = force_artifact()
        self.login("mdm.delete_artifact", "mdm.view_artifact")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:delete_artifact", args=(artifact.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        event = self.assert_audit_event(post_event, callbacks, "deleted", "mdm.artifact", artifact.pk)
        self.assertEqual(event.payload["object"]["prev_value"]["name"], artifact.name)

    # blueprint artifacts

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_blueprint_artifact_audit_event(self, post_event):
        artifact, _ = force_artifact()
        blueprint = force_blueprint()
        self.login("mdm.add_blueprintartifact", "mdm.view_artifact")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:create_blueprint_artifact", args=(artifact.pk,)),
                                        {"blueprint": blueprint.pk,
                                         "shard_modulo": 10,
                                         "default_shard": 5,
                                         "macos": "on"},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        blueprint_artifact = blueprint.blueprintartifact_set.get(artifact=artifact)
        self.assert_audit_event(post_event, callbacks, "created",
                                "mdm.blueprintartifact", blueprint_artifact.pk)
        # the audit event must not get in the way of the blueprint refresh
        blueprint.refresh_from_db()
        self.assertEqual(set(blueprint.serialized_artifacts), {str(artifact.pk)})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_blueprint_artifact_audit_event(self, post_event):
        blueprint_artifact, artifact, _ = force_blueprint_artifact()
        self.login("mdm.change_blueprintartifact", "mdm.view_artifact")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("mdm:update_blueprint_artifact", args=(artifact.pk, blueprint_artifact.pk)),
                {"blueprint": blueprint_artifact.blueprint.pk,
                 "shard_modulo": 20,
                 "default_shard": 4,
                 "macos": "on"},
                follow=True)
        self.assertEqual(response.status_code, 200)
        event = self.assert_audit_event(post_event, callbacks, "updated",
                                        "mdm.blueprintartifact", blueprint_artifact.pk)
        self.assertEqual(event.payload["object"]["new_value"]["shard_modulo"], 20)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_blueprint_artifact_audit_event(self, post_event):
        blueprint_artifact, artifact, _ = force_blueprint_artifact()
        blueprint = blueprint_artifact.blueprint
        self.login("mdm.delete_blueprintartifact", "mdm.view_artifact")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("mdm:delete_blueprint_artifact", args=(artifact.pk, blueprint_artifact.pk)),
                follow=True)
        self.assertEqual(response.status_code, 200)
        self.assert_audit_event(post_event, callbacks, "deleted",
                                "mdm.blueprintartifact", blueprint_artifact.pk)
        # the event is built before the delete, and the blueprint refresh still runs after it
        blueprint.refresh_from_db()
        self.assertEqual(blueprint.serialized_artifacts, {})

    # artifact versions

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_artifact_version_audit_event(self, post_event):
        artifact, (artifact_version,) = force_artifact()
        self.login("mdm.change_artifactversion", "mdm.view_artifactversion")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("mdm:update_artifact_version", args=(artifact.pk, artifact_version.pk)),
                {"default_shard": 8, "shard_modulo": 88, "macos": "on"},
                follow=True)
        self.assertEqual(response.status_code, 200)
        event = self.assert_audit_event(post_event, callbacks, "updated",
                                        "mdm.artifactversion", artifact_version.pk)
        self.assertEqual(event.payload["object"]["new_value"]["shard_modulo"], 88)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_artifact_version_audit_event(self, post_event):
        artifact, (artifact_version, artifact_version2) = force_artifact(version_count=2)
        self.login("mdm.delete_artifactversion", "mdm.view_artifact")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("mdm:delete_artifact_version", args=(artifact.pk, artifact_version2.pk)),
                follow=True)
        self.assertEqual(response.status_code, 200)
        self.assert_audit_event(post_event, callbacks, "deleted",
                                "mdm.artifactversion", artifact_version2.pk)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_upgrade_artifact_version_audit_event(self, post_event):
        # BaseUpgradeArtifactVersionView, so every upgrade form is covered
        bpa, artifact, (artifact_version,) = force_blueprint_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        declaration = artifact_version.declaration
        self.login("mdm.add_artifactversion", "mdm.view_artifactversion")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:upgrade_declaration", args=(artifact.pk,)),
                                        {"source": json.dumps({
                                            "Identifier": declaration.identifier,
                                            "Type": declaration.type,
                                            "Payload": {"Restrictions": {"ExternalStorage": "Disallowed"}}}),
                                         "default_shard": 9,
                                         "shard_modulo": 99,
                                         "macos": "on"},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        new_artifact_version = response.context["object"]
        self.assertEqual(new_artifact_version.version, 2)
        self.assert_audit_event(post_event, callbacks, "created",
                                "mdm.artifactversion", new_artifact_version.pk)

    # store app artifact, created from an asset

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_asset_artifact_audit_event(self, post_event):
        location_asset = force_location_asset()
        self.login("mdm.view_asset", "mdm.add_artifact", "mdm.view_artifact")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("mdm:create_asset_artifact", args=(location_asset.asset.pk,)),
                {"name": name,
                 "location_asset": location_asset.pk,
                 "configuration": plistlib.dumps({"yolo": "fomo"}).decode("utf-8"),
                 "remove_on_unenroll": "on",
                 "prevent_backup": "on"},
                follow=True)
        self.assertEqual(response.status_code, 200)
        artifact = Artifact.objects.get(name=name)
        self.assert_audit_event(post_event, callbacks, "created", "mdm.artifact", artifact.pk)

from unittest.mock import patch
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import APIToken, User
from tests.zentral_test_utils.login_case import LoginCase
from tests.zentral_test_utils.request_case import RequestCase
from zentral.contrib.inventory.models import Tag
from zentral.contrib.mdm.models import BlueprintArtifact
from zentral.core.events.base import AuditEvent
from .utils import force_artifact, force_blueprint, force_blueprint_artifact


class MDMBlueprintArtifactsAPIViewsTestCase(TestCase, LoginCase, RequestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True
        )
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        cls.user.groups.set([cls.group])
        _, cls.api_key = APIToken.objects.create_for_user(cls.service_account)

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "mdm_api"

    # RequestCase implementation

    def _get_api_key(self):
        return self.api_key

    # list blueprint artifacts

    def test_list_blueprint_artifacts_unauthorized(self):
        response = self.get(reverse("mdm_api:blueprint_artifacts"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_blueprint_artifacts_permission_denied(self):
        response = self.get(reverse("mdm_api:blueprint_artifacts"))
        self.assertEqual(response.status_code, 403)

    def test_list_blueprint_artifacts(self):
        blueprint_artifact, artifact, _ = force_blueprint_artifact()
        self.set_permissions("mdm.view_blueprintartifact")
        response = self.get(reverse("mdm_api:blueprint_artifacts"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'id': blueprint_artifact.pk,
              'blueprint': blueprint_artifact.blueprint.pk,
              'artifact': str(artifact.pk),
              'default_shard': 100,
              'excluded_tags': [],
              'ios': False,
              'ios_max_version': '',
              'ios_min_version': '',
              'ipados': False,
              'ipados_max_version': '',
              'ipados_min_version': '',
              'macos': True,
              'macos_max_version': '',
              'macos_min_version': '',
              'shard_modulo': 100,
              'tag_shards': [],
              'tvos': False,
              'tvos_max_version': '',
              'tvos_min_version': '',
              'created_at': blueprint_artifact.created_at.isoformat(),
              'updated_at': blueprint_artifact.updated_at.isoformat()}]
        )

    # get blueprint artifact

    def test_get_blueprint_artifact_unauthorized(self):
        blueprint_artifact, _, _ = force_blueprint_artifact()
        response = self.get(reverse("mdm_api:blueprint_artifact", args=(blueprint_artifact.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_blueprint_artifact_permission_denied(self):
        blueprint_artifact, _, _ = force_blueprint_artifact()
        response = self.get(reverse("mdm_api:blueprint_artifact", args=(blueprint_artifact.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_blueprint_artifact(self):
        force_blueprint_artifact()
        blueprint_artifact, artifact, _ = force_blueprint_artifact()
        self.set_permissions("mdm.view_blueprintartifact")
        response = self.get(reverse("mdm_api:blueprint_artifact", args=(blueprint_artifact.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'id': blueprint_artifact.pk,
             'blueprint': blueprint_artifact.blueprint.pk,
             'artifact': str(artifact.pk),
             'default_shard': 100,
             'excluded_tags': [],
             'ios': False,
             'ios_max_version': '',
             'ios_min_version': '',
             'ipados': False,
             'ipados_max_version': '',
             'ipados_min_version': '',
             'macos': True,
             'macos_max_version': '',
             'macos_min_version': '',
             'shard_modulo': 100,
             'tag_shards': [],
             'tvos': False,
             'tvos_max_version': '',
             'tvos_min_version': '',
             'created_at': blueprint_artifact.created_at.isoformat(),
             'updated_at': blueprint_artifact.updated_at.isoformat()}
        )

    # create blueprint artifact

    def test_create_blueprint_artifact_unauthorized(self):
        response = self.post(reverse("mdm_api:blueprint_artifacts"),
                             {"name": get_random_string(12)},
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_blueprint_artifact_permission_denied(self):
        response = self.post(reverse("mdm_api:blueprint_artifacts"),
                             {"name": get_random_string(12)})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_blueprint_artifact(self, post_event):
        blueprint = force_blueprint()
        artifact, _ = force_artifact()
        self.assertEqual(len(blueprint.serialized_artifacts), 0)
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        self.set_permissions("mdm.add_blueprintartifact")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(reverse("mdm_api:blueprint_artifacts"),
                                 {"blueprint": blueprint.pk,
                                  "artifact": artifact.pk,
                                  "macos": True,
                                  "macos_max_version": "",
                                  "macos_min_version": "13.3.1",
                                  "excluded_tags": [excluded_tag.pk],
                                  "shard_modulo": 10,
                                  "default_shard": 0,
                                  "tag_shards": [{"tag": shard_tag.pk, "shard": 5}]})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        blueprint_artifact = BlueprintArtifact.objects.get(blueprint=blueprint, artifact=artifact)
        self.assertEqual(
            response.json(),
            {'id': blueprint_artifact.pk,
             'blueprint': blueprint_artifact.blueprint.pk,
             'artifact': str(artifact.pk),
             'default_shard': 0,
             'excluded_tags': [excluded_tag.pk],
             'ios': False,
             'ios_max_version': '',
             'ios_min_version': '',
             'ipados': False,
             'ipados_max_version': '',
             'ipados_min_version': '',
             'macos': True,
             'macos_max_version': '',
             'macos_min_version': '13.3.1',
             'shard_modulo': 10,
             'tag_shards': [{"tag": shard_tag.pk, "shard": 5}],
             'tvos': False,
             'tvos_max_version': '',
             'tvos_min_version': '',
             'created_at': blueprint_artifact.created_at.isoformat(),
             'updated_at': blueprint_artifact.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "mdm.blueprintartifact",
                 "pk": str(blueprint_artifact.pk),
                 "new_value": {
                     "pk": blueprint_artifact.pk,
                     "blueprint": {"pk": blueprint.pk, "name": blueprint.name},
                     "artifact": {"pk": str(artifact.pk), "name": artifact.name},
                     'default_shard': 0,
                     'excluded_tags': [{"pk": excluded_tag.pk, "name": excluded_tag.name}],
                     'ios': False,
                     'ios_max_version': '',
                     'ios_min_version': '',
                     'ipados': False,
                     'ipados_max_version': '',
                     'ipados_min_version': '',
                     'macos': True,
                     'macos_max_version': '',
                     'macos_min_version': '13.3.1',
                     'shard_modulo': 10,
                     'tag_shards': [{"tag": {"pk": shard_tag.pk, "name": shard_tag.name}, "shard": 5}],
                     'tvos': False,
                     'tvos_max_version': '',
                     'tvos_min_version': '',
                     "created_at": blueprint_artifact.created_at,
                     "updated_at": blueprint_artifact.updated_at
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_blueprint_artifact": [str(blueprint_artifact.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        blueprint.refresh_from_db()
        self.assertEqual(len(blueprint.serialized_artifacts), 1)

    # update blueprint

    def test_update_blueprint_artifact_unauthorized(self):
        blueprint_artifact, artifact, _ = force_blueprint_artifact()
        response = self.put(reverse("mdm_api:blueprint_artifact", args=(blueprint_artifact.pk,)),
                            {"blueprint": blueprint_artifact.blueprint.pk,
                             "artifact": artifact.pk,
                             "macos": True},
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_blueprint_artifact_permission_denied(self):
        blueprint_artifact, artifact, _ = force_blueprint_artifact()
        response = self.put(reverse("mdm_api:blueprint_artifact", args=(blueprint_artifact.pk,)),
                            {"blueprint": blueprint_artifact.blueprint.pk,
                             "artifact": artifact.pk,
                             "macos": True})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_blueprint_artifact(self, post_event):
        blueprint_artifact, artifact, _ = force_blueprint_artifact()
        blueprint = blueprint_artifact.blueprint
        self.assertIsNone(blueprint.serialized_artifacts[str(artifact.pk)]["macos_min_version"])
        prev_value = blueprint_artifact.serialize_for_event()
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        self.set_permissions("mdm.change_blueprintartifact")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(reverse("mdm_api:blueprint_artifact", args=(blueprint_artifact.pk,)),
                                {"blueprint": blueprint.pk,
                                 "artifact": artifact.pk,
                                 "macos": True,
                                 "macos_max_version": "",
                                 "macos_min_version": "13.3.1",
                                 "excluded_tags": [excluded_tag.pk],
                                 "shard_modulo": 10,
                                 "default_shard": 0,
                                 "tag_shards": [{"tag": shard_tag.pk, "shard": 5}]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        blueprint_artifact.refresh_from_db()
        self.assertEqual(blueprint_artifact.macos_min_version, "13.3.1")
        self.assertEqual(blueprint_artifact.shard_modulo, 10)
        self.assertEqual(blueprint_artifact.default_shard, 0)
        self.assertEqual(
            response.json(),
            {'id': blueprint_artifact.pk,
             'blueprint': blueprint_artifact.blueprint.pk,
             'artifact': str(artifact.pk),
             'default_shard': 0,
             'excluded_tags': [excluded_tag.pk],
             'ios': False,
             'ios_max_version': '',
             'ios_min_version': '',
             'ipados': False,
             'ipados_max_version': '',
             'ipados_min_version': '',
             'macos': True,
             'macos_max_version': '',
             'macos_min_version': '13.3.1',
             'shard_modulo': 10,
             'tag_shards': [{"tag": shard_tag.pk, "shard": 5}],
             'tvos': False,
             'tvos_max_version': '',
             'tvos_min_version': '',
             'created_at': blueprint_artifact.created_at.isoformat(),
             'updated_at': blueprint_artifact.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "mdm.blueprintartifact",
                 "pk": str(blueprint_artifact.pk),
                 "new_value": {
                     "pk": blueprint_artifact.pk,
                     "blueprint": {"pk": blueprint.pk, "name": blueprint.name},
                     "artifact": {"pk": str(artifact.pk), "name": artifact.name},
                     'default_shard': 0,
                     'excluded_tags': [{"pk": excluded_tag.pk, "name": excluded_tag.name}],
                     'ios': False,
                     'ios_max_version': '',
                     'ios_min_version': '',
                     'ipados': False,
                     'ipados_max_version': '',
                     'ipados_min_version': '',
                     'macos': True,
                     'macos_max_version': '',
                     'macos_min_version': '13.3.1',
                     'shard_modulo': 10,
                     'tag_shards': [{"tag": {"pk": shard_tag.pk, "name": shard_tag.name}, "shard": 5}],
                     'tvos': False,
                     'tvos_max_version': '',
                     'tvos_min_version': '',
                     "created_at": blueprint_artifact.created_at,
                     "updated_at": blueprint_artifact.updated_at
                 },
                 "prev_value": prev_value
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_blueprint_artifact": [str(blueprint_artifact.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        blueprint.refresh_from_db()
        self.assertEqual(blueprint.serialized_artifacts[str(artifact.pk)]["macos_min_version"], [13, 3, 1])

    # delete blueprint artifact

    def test_delete_blueprint_artifact_unauthorized(self):
        blueprint_artifact, _, _ = force_blueprint_artifact()
        response = self.delete(reverse("mdm_api:blueprint_artifact", args=(blueprint_artifact.pk,)),
                               include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_blueprint_artifact_permission_denied(self):
        blueprint_artifact, _, _ = force_blueprint_artifact()
        response = self.delete(reverse("mdm_api:blueprint_artifact", args=(blueprint_artifact.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_blueprint_artifact(self, post_event):
        blueprint_artifact, _, _ = force_blueprint_artifact()
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(len(blueprint.serialized_artifacts), 1)
        prev_value = blueprint_artifact.serialize_for_event()
        self.set_permissions("mdm.delete_blueprintartifact")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("mdm_api:blueprint_artifact", args=(blueprint_artifact.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(BlueprintArtifact.objects.filter(pk=blueprint_artifact.pk).count(), 0)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "mdm.blueprintartifact",
                 "pk": str(blueprint_artifact.pk),
                 "prev_value": prev_value
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_blueprint_artifact": [str(blueprint_artifact.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        blueprint.refresh_from_db()
        self.assertEqual(len(blueprint.serialized_artifacts), 0)

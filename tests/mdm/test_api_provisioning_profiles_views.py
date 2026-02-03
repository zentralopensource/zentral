import base64
from functools import reduce
import hashlib
import operator
from unittest.mock import patch
import uuid
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase
from accounts.models import APIToken, User
from zentral.contrib.inventory.models import MetaBusinessUnit, Tag
from zentral.contrib.mdm.models import Artifact, ArtifactVersion, ArtifactVersionTag, DeviceArtifact, TargetArtifact
from zentral.core.events.base import AuditEvent
from .utils import (build_provisioning_profile, build_provisioning_profile_content,
                    force_artifact, force_blueprint_artifact, force_dep_enrollment_session)


class MDMProvisioningProfilesAPIViewsTestCase(TestCase):
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

    # utility methods

    def set_permissions(self, *permissions):
        if permissions:
            permission_filter = reduce(operator.or_, (
                Q(content_type__app_label=app_label, codename=codename)
                for app_label, codename in (
                    permission.split(".")
                    for permission in permissions
                )
            ))
            self.group.permissions.set(list(Permission.objects.filter(permission_filter)))
        else:
            self.group.permissions.clear()

    def _make_request(self, method, url, data=None, include_token=True):
        kwargs = {}
        if data is not None:
            kwargs["content_type"] = "application/json"
            kwargs["data"] = data
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return method(url, **kwargs)

    def delete(self, *args, **kwargs):
        return self._make_request(self.client.delete, *args, **kwargs)

    def get(self, *args, **kwargs):
        return self._make_request(self.client.get, *args, **kwargs)

    def post(self, *args, **kwargs):
        return self._make_request(self.client.post, *args, **kwargs)

    def put(self, *args, **kwargs):
        return self._make_request(self.client.put, *args, **kwargs)

    # list provisioning profiles

    def test_list_provisioning_profiles_unauthorized(self):
        response = self.get(reverse("mdm_api:provisioning_profiles"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_provisioning_profiles_permission_denied(self):
        response = self.get(reverse("mdm_api:provisioning_profiles"))
        self.assertEqual(response.status_code, 403)

    def test_list_provisioning_profiles(self):
        artifact, (av,) = force_artifact(artifact_type=Artifact.Type.PROVISIONING_PROFILE)
        self.set_permissions("mdm.view_provisioningprofile")
        response = self.get(reverse("mdm_api:provisioning_profiles"))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(
            data,
            {'count': 1,
             'next': None,
             'previous': None,
             'results': [
                 {'id': str(av.pk),
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
                  'source': base64.b64encode(av.provisioning_profile.source).decode("ascii"),
                  'tag_shards': [],
                  'tvos': False,
                  'tvos_max_version': '',
                  'tvos_min_version': '',
                  'version': av.version,
                  'created_at': av.created_at.isoformat(),
                  'updated_at': av.updated_at.isoformat()}
              ]}
        )

    # create provisioning profile

    def test_create_provisioning_profile_unauthorized(self):
        artifact, _ = force_artifact()
        response = self.post(reverse("mdm_api:provisioning_profiles"),
                             data={"artifact": str(artifact.pk),
                                   "source": base64.b64encode(build_provisioning_profile()).decode("ascii"),
                                   "macos": True,
                                   "version": 2},
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_provisioning_profile_permission_denied(self):
        artifact, _ = force_artifact()
        response = self.post(reverse("mdm_api:provisioning_profiles"),
                             data={"artifact": str(artifact.pk),
                                   "source": base64.b64encode(build_provisioning_profile()).decode("ascii"),
                                   "macos": True,
                                   "version": 2})
        self.assertEqual(response.status_code, 403)

    def test_create_provisioning_profile_no_source(self):
        artifact, _ = force_artifact()
        self.set_permissions("mdm.add_provisioningprofile")
        response = self.post(reverse("mdm_api:provisioning_profiles"),
                             data={"artifact": str(artifact.pk),
                                   "macos": True,
                                   "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'source': ['This field is required.']})

    def test_create_provisioning_profile_empty_source(self):
        artifact, _ = force_artifact()
        self.set_permissions("mdm.add_provisioningprofile")
        response = self.post(reverse("mdm_api:provisioning_profiles"),
                             data={"artifact": str(artifact.pk),
                                   "source": "",
                                   "macos": True,
                                   "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'source': ['Could not verify signature']})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_provisioning_profile(self, post_event):
        blueprint_artifact, artifact, (av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.PROVISIONING_PROFILE
        )
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 1)
        self.set_permissions("mdm.add_provisioningprofile")
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        name = get_random_string(12)
        pp_uuid = uuid.uuid4()
        content = build_provisioning_profile_content(name, pp_uuid)
        source = base64.b64encode(build_provisioning_profile(content=content)).decode("ascii")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(reverse("mdm_api:provisioning_profiles"),
                                 data={"artifact": str(artifact.pk),
                                       "source": source,
                                       "macos": True,
                                       "macos_max_version": "",  # blank OK
                                       "macos_min_version": "13.3.1",
                                       "excluded_tags": [excluded_tag.pk],
                                       "shard_modulo": 10,
                                       "default_shard": 0,
                                       "tag_shards": [{"tag": shard_tag.pk, "shard": 5}],
                                       "version": 17})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        data = response.json()
        data.pop("source")
        av = artifact.artifactversion_set.all().order_by("-created_at").first()
        self.assertEqual(
            data,
            {'id': str(av.pk),
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
             'version': 17,
             'created_at': av.created_at.isoformat(),
             'updated_at': av.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "mdm.provisioningprofile",
                 "pk": str(av.provisioning_profile.pk),
                 "new_value": {
                     "pk": str(av.pk),
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
                     'name': name,
                     'shard_modulo': 10,
                     'tag_shards': [{"tag": {"pk": shard_tag.pk, "name": shard_tag.name}, "shard": 5}],
                     'tvos': False,
                     'tvos_max_version': '',
                     'tvos_min_version': '',
                     'uuid': str(pp_uuid),
                     'version': 17,
                     'source': hashlib.sha1(av.provisioning_profile.source).hexdigest(),
                     "created_at": av.created_at,
                     "updated_at": av.updated_at
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_provisioning_profile": [str(av.provisioning_profile.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        blueprint.refresh_from_db()
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 2)

    # get provisioning profile

    def test_get_provisioning_profile_unauthorized(self):
        _, (av,) = force_artifact(artifact_type=Artifact.Type.PROVISIONING_PROFILE)
        response = self.get(reverse("mdm_api:provisioning_profile", args=(av.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_provisioning_profile_permission_denied(self):
        _, (av,) = force_artifact(artifact_type=Artifact.Type.PROVISIONING_PROFILE)
        response = self.get(reverse("mdm_api:provisioning_profile", args=(av.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_artifact(self):
        force_artifact(artifact_type=Artifact.Type.PROVISIONING_PROFILE)
        artifact, (av,) = force_artifact(artifact_type=Artifact.Type.PROVISIONING_PROFILE)
        self.set_permissions("mdm.view_provisioningprofile")
        response = self.get(reverse("mdm_api:provisioning_profile", args=(av.pk,)))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        data.pop("source")
        self.assertEqual(
            data,
            {'id': str(av.pk),
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
             'version': av.version,
             'created_at': av.created_at.isoformat(),
             'updated_at': av.updated_at.isoformat()}
        )

    # update provisioning profile

    def test_update_provisioning_profile_unauthorized(self):
        artifact, (av,) = force_artifact(artifact_type=Artifact.Type.PROVISIONING_PROFILE)
        response = self.put(reverse("mdm_api:provisioning_profile", args=(av.pk,)),
                            data={"artifact": str(artifact.pk),
                                  "source": base64.b64encode(build_provisioning_profile()).decode("ascii"),
                                  "macos": True},
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_provisioning_profile_permission_denied(self):
        artifact, (av,) = force_artifact(artifact_type=Artifact.Type.PROVISIONING_PROFILE)
        response = self.put(reverse("mdm_api:provisioning_profile", args=(av.pk,)),
                            data={"artifact": str(artifact.pk),
                                  "source": base64.b64encode(build_provisioning_profile()).decode("ascii"),
                                  "macos": True})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_provisioning_profile(self, post_event):
        blueprint_artifact, artifact, (av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.PROVISIONING_PROFILE,
        )
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(blueprint.serialized_artifacts[str(artifact.pk)]["versions"][0]["excluded_tags"], [])
        av.excluded_tags.set([Tag.objects.create(name=get_random_string(12))])
        ArtifactVersionTag.objects.create(artifact_version=av,
                                          tag=Tag.objects.create(name=get_random_string(12)),
                                          shard=1)
        prev_value = av.provisioning_profile.serialize_for_event()
        self.set_permissions("mdm.change_provisioningprofile")
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        name = get_random_string(12)
        pp_uuid = uuid.uuid4()
        content = build_provisioning_profile_content(name, pp_uuid)
        source = base64.b64encode(build_provisioning_profile(content=content)).decode("ascii")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(reverse("mdm_api:provisioning_profile", args=(av.pk,)),
                                data={"artifact": str(artifact.pk),
                                      "source": source,
                                      "macos": True,
                                      "macos_min_version": "13.3.1",
                                      "excluded_tags": [excluded_tag.pk],
                                      "shard_modulo": 10,
                                      "default_shard": 0,
                                      "tag_shards": [{"tag": shard_tag.pk, "shard": 5}],
                                      "version": 17})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        data = response.json()
        data.pop("source")
        av.refresh_from_db()
        self.assertEqual(
            data,
            {'id': str(av.pk),
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
             'version': 17,
             'created_at': av.created_at.isoformat(),
             'updated_at': av.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "mdm.provisioningprofile",
                 "pk": str(av.provisioning_profile.pk),
                 "new_value": {
                     "pk": str(av.pk),
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
                     'name': name,
                     'shard_modulo': 10,
                     'tag_shards': [{"tag": {"pk": shard_tag.pk, "name": shard_tag.name}, "shard": 5}],
                     'tvos': False,
                     'tvos_max_version': '',
                     'tvos_min_version': '',
                     'uuid': str(pp_uuid),
                     'version': 17,
                     'source': hashlib.sha1(av.provisioning_profile.source).hexdigest(),
                     "created_at": av.created_at,
                     "updated_at": av.updated_at
                 },
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_provisioning_profile": [str(av.provisioning_profile.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        blueprint.refresh_from_db()
        self.assertEqual(blueprint.serialized_artifacts[str(artifact.pk)]["versions"][0]["excluded_tags"],
                         [excluded_tag.pk])

    # delete provisioning profile

    def test_delete_provisioning_profile_unauthorized(self):
        artifact, (av,) = force_artifact(artifact_type=Artifact.Type.PROVISIONING_PROFILE)
        response = self.delete(reverse("mdm_api:provisioning_profile", args=(av.pk,)),
                               include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_provisioning_profile_permission_denied(self):
        artifact, (av,) = force_artifact(artifact_type=Artifact.Type.PROVISIONING_PROFILE)
        response = self.delete(reverse("mdm_api:provisioning_profile", args=(av.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_provisioning_profile_cannot_be_deleted(self):
        artifact, (av,) = force_artifact(artifact_type=Artifact.Type.PROVISIONING_PROFILE)
        session, _, _ = force_dep_enrollment_session(MetaBusinessUnit.objects.create(name=get_random_string(12)),
                                                     completed=True)
        DeviceArtifact.objects.create(
            enrolled_device=session.enrolled_device,
            artifact_version=av,
            status=TargetArtifact.Status.ACKNOWLEDGED,
        )
        self.set_permissions("mdm.delete_provisioningprofile")
        response = self.delete(reverse("mdm_api:provisioning_profile", args=(av.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ["This provisioning profile cannot be deleted"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_provisioning_profile(self, post_event):
        blueprint_artifact, artifact, (av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.PROVISIONING_PROFILE,
        )
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 1)
        self.assertEqual(blueprint.serialized_artifacts[str(artifact.pk)]["versions"][0]["pk"],
                         str(av.pk))
        prev_value = av.provisioning_profile.serialize_for_event()
        self.set_permissions("mdm.delete_provisioningprofile")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("mdm_api:provisioning_profile", args=(av.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "mdm.provisioningprofile",
                 "pk": str(av.provisioning_profile.pk),
                 "prev_value": prev_value,
             }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_provisioning_profile": [str(av.provisioning_profile.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        self.assertEqual(ArtifactVersion.objects.filter(pk=av.pk).count(), 0)
        blueprint.refresh_from_db()
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 0)

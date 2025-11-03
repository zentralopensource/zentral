import base64
from functools import reduce
import hashlib
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from accounts.models import APIToken, User
from zentral.contrib.inventory.models import MetaBusinessUnit, Tag
from zentral.contrib.mdm.models import ArtifactVersion, ArtifactVersionTag, DeviceArtifact, TargetArtifact
from zentral.core.events.base import AuditEvent
from .utils import build_mobileconfig_data, force_artifact, force_blueprint_artifact, force_dep_enrollment_session


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MDMProfilesAPIViewsTestCase(TestCase):
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
        _, cls.api_key = APIToken.objects.update_or_create_for_user(cls.service_account)

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

    def login(self, *permissions):
        self.set_permissions(*permissions)
        self.client.force_login(self.user)

    def login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

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

    # list profiles

    def test_list_profiles_unauthorized(self):
        response = self.get(reverse("mdm_api:profiles"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_profiles_permission_denied(self):
        response = self.get(reverse("mdm_api:profiles"))
        self.assertEqual(response.status_code, 403)

    def test_list_profiles(self):
        artifact, (profile_av,) = force_artifact()
        self.set_permissions("mdm.view_profile")
        response = self.get(reverse("mdm_api:profiles"))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        for obj in data:
            obj.pop("source")
        self.assertEqual(
            data,
            [{'id': str(profile_av.pk),
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
              'version': profile_av.version,
              'created_at': profile_av.created_at.isoformat(),
              'updated_at': profile_av.updated_at.isoformat()}]
        )

    # create profile

    def test_create_profile_unauthorized(self):
        artifact, _ = force_artifact()
        response = self.post(reverse("mdm_api:profiles"),
                             data={"artifact": str(artifact.pk),
                                   "source": base64.b64encode(build_mobileconfig_data()).decode("ascii"),
                                   "macos": True},
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_profile_permission_denied(self):
        artifact, _ = force_artifact()
        response = self.post(reverse("mdm_api:profiles"),
                             data={"artifact": str(artifact.pk),
                                   "source": base64.b64encode(build_mobileconfig_data()).decode("ascii"),
                                   "macos": True})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_profile(self, post_event):
        blueprint_artifact, artifact, (profile_av,) = force_blueprint_artifact()
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 1)
        self.set_permissions("mdm.add_profile")
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(reverse("mdm_api:profiles"),
                                 data={"artifact": str(artifact.pk),
                                       "source": base64.b64encode(build_mobileconfig_data()).decode("ascii"),
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
        profile_av = artifact.artifactversion_set.all().order_by("-created_at").first()
        self.assertEqual(
            data,
            {'id': str(profile_av.pk),
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
             'created_at': profile_av.created_at.isoformat(),
             'updated_at': profile_av.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "mdm.profile",
                 "pk": str(profile_av.profile.pk),
                 "new_value": {
                     "pk": str(profile_av.pk),
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
                     'version': 17,
                     'source': hashlib.sha1(profile_av.profile.source).hexdigest(),
                     'filename': '',
                     'payload_description': 'Auto-date&time, no in-app '
                                            'purchase, for test purpose '
                                            'blocked: no Siri no siri '
                                            'suggestions, no AirPrint',
                     'payload_display_name': 'iOS Restrictions',
                     'payload_identifier': 'com.example.my-profile',
                     'payload_uuid': '8846C027-9F51-4574-9042-33C118F3D43E',
                     "created_at": profile_av.created_at,
                     "updated_at": profile_av.updated_at
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_profile": [str(profile_av.profile.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        blueprint.refresh_from_db()
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 2)

    # get profile

    def test_get_profile_unauthorized(self):
        artifact, (profile_av,) = force_artifact()
        response = self.get(reverse("mdm_api:profile", args=(profile_av.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_profile_permission_denied(self):
        artifact, (profile_av,) = force_artifact()
        response = self.get(reverse("mdm_api:profile", args=(profile_av.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_artifact(self):
        force_artifact()
        artifact, (profile_av,) = force_artifact()
        self.set_permissions("mdm.view_profile")
        response = self.get(reverse("mdm_api:profile", args=(profile_av.pk,)))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        data.pop("source")
        self.assertEqual(
            data,
            {'id': str(profile_av.pk),
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
             'version': profile_av.version,
             'created_at': profile_av.created_at.isoformat(),
             'updated_at': profile_av.updated_at.isoformat()}
        )

    # update profile

    def test_update_profile_unauthorized(self):
        artifact, (profile_av,) = force_artifact()
        response = self.put(reverse("mdm_api:profile", args=(profile_av.pk,)),
                            data={"artifact": str(artifact.pk),
                                  "source": base64.b64encode(build_mobileconfig_data()).decode("ascii"),
                                  "macos": True},
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_profile_permission_denied(self):
        artifact, (profile_av,) = force_artifact()
        response = self.put(reverse("mdm_api:profile", args=(profile_av.pk,)),
                            data={"artifact": str(artifact.pk),
                                  "source": base64.b64encode(build_mobileconfig_data()).decode("ascii"),
                                  "macos": True})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_profile(self, post_event):
        blueprint_artifact, artifact, (profile_av,) = force_blueprint_artifact()
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(blueprint.serialized_artifacts[str(artifact.pk)]["versions"][0]["excluded_tags"], [])
        profile_av.excluded_tags.set([Tag.objects.create(name=get_random_string(12))])
        ArtifactVersionTag.objects.create(artifact_version=profile_av,
                                          tag=Tag.objects.create(name=get_random_string(12)),
                                          shard=1)
        prev_value = profile_av.profile.serialize_for_event()
        self.set_permissions("mdm.change_profile")
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(reverse("mdm_api:profile", args=(profile_av.pk,)),
                                data={"artifact": str(artifact.pk),
                                      "source": base64.b64encode(build_mobileconfig_data()).decode("ascii"),
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
        profile_av.refresh_from_db()
        self.assertEqual(
            data,
            {'id': str(profile_av.pk),
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
             'created_at': profile_av.created_at.isoformat(),
             'updated_at': profile_av.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "mdm.profile",
                 "pk": str(profile_av.profile.pk),
                 "new_value": {
                     "pk": str(profile_av.pk),
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
                     'version': 17,
                     'source': hashlib.sha1(profile_av.profile.source).hexdigest(),
                     'filename': '',
                     'payload_description': 'Auto-date&time, no in-app '
                                            'purchase, for test purpose '
                                            'blocked: no Siri no siri '
                                            'suggestions, no AirPrint',
                     'payload_display_name': 'iOS Restrictions',
                     'payload_identifier': 'com.example.my-profile',
                     'payload_uuid': '8846C027-9F51-4574-9042-33C118F3D43E',
                     "created_at": profile_av.created_at,
                     "updated_at": profile_av.updated_at
                 },
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_profile": [str(profile_av.profile.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        blueprint.refresh_from_db()
        self.assertEqual(blueprint.serialized_artifacts[str(artifact.pk)]["versions"][0]["excluded_tags"],
                         [excluded_tag.pk])

    # delete profile

    def test_delete_profile_unauthorized(self):
        artifact, (profile_av,) = force_artifact()
        response = self.delete(reverse("mdm_api:profile", args=(profile_av.pk,)),
                               include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_profile_permission_denied(self):
        artifact, (profile_av,) = force_artifact()
        response = self.delete(reverse("mdm_api:profile", args=(profile_av.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_profile_cannot_be_deleted(self):
        artifact, (profile_av,) = force_artifact()
        session, _, _ = force_dep_enrollment_session(MetaBusinessUnit.objects.create(name=get_random_string(12)),
                                                     completed=True)
        DeviceArtifact.objects.create(
            enrolled_device=session.enrolled_device,
            artifact_version=profile_av,
            status=TargetArtifact.Status.INSTALLED
        )
        self.set_permissions("mdm.delete_profile")
        response = self.delete(reverse("mdm_api:profile", args=(profile_av.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ["This profile cannot be deleted"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_profile(self, post_event):
        blueprint_artifact, artifact, (profile_av,) = force_blueprint_artifact()
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 1)
        self.assertEqual(blueprint.serialized_artifacts[str(artifact.pk)]["versions"][0]["pk"],
                         str(profile_av.pk))
        prev_value = profile_av.profile.serialize_for_event()
        self.set_permissions("mdm.delete_profile")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("mdm_api:profile", args=(profile_av.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "mdm.profile",
                 "pk": str(profile_av.profile.pk),
                 "prev_value": prev_value,
             }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_profile": [str(profile_av.profile.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        self.assertEqual(ArtifactVersion.objects.filter(pk=profile_av.pk).count(), 0)
        blueprint.refresh_from_db()
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 0)

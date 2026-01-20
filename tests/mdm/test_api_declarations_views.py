from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase
from accounts.models import APIToken, User
from zentral.contrib.inventory.models import MetaBusinessUnit, Tag
from zentral.contrib.mdm.models import (Artifact, ArtifactVersion, ArtifactVersionTag,
                                        DeclarationRef, DeviceArtifact, TargetArtifact)
from zentral.core.events.base import AuditEvent
from .utils import force_artifact, force_blueprint_artifact, force_dep_enrollment_session


class MDMDeclarationsAPIViewsTestCase(TestCase):
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

    # list declarations

    def test_list_declarations_unauthorized(self):
        response = self.get(reverse("mdm_api:declarations"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_declarations_permission_denied(self):
        response = self.get(reverse("mdm_api:declarations"))
        self.assertEqual(response.status_code, 403)

    def test_list_declarations(self):
        artifact, (av,) = force_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        self.set_permissions("mdm.view_declaration")
        response = self.get(reverse("mdm_api:declarations"))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(
            data,
            [{'id': str(av.pk),
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
              'source': {
                  'Identifier': av.declaration.identifier,
                  'Payload': {'Restrictions': {'ExternalStorage': 'Disallowed',
                                               'NetworkStorage': 'Disallowed'}},
                  'ServerToken': av.declaration.server_token,
                  'Type': 'com.apple.configuration.diskmanagement.settings'
              },
              'tag_shards': [],
              'tvos': False,
              'tvos_max_version': '',
              'tvos_min_version': '',
              'version': av.version,
              'created_at': av.created_at.isoformat(),
              'updated_at': av.updated_at.isoformat()}]
        )

    # create declaration

    def test_create_declaration_unauthorized(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        response = self.post(reverse("mdm_api:declarations"),
                             data={"artifact": str(artifact.pk),
                                   "source": {
                                       "Type": "com.apple.configuration.passcode.settings",
                                       "Identifier": "com.example.ddm.1",
                                       "ServerToken": "8cbb059c-326a-4ad8-8ffc-ea6c72e368a1",
                                       "Payload": {"MinimumLength": 10},
                                   },
                                   "macos": True},
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_declaration_permission_denied(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        response = self.post(reverse("mdm_api:declarations"),
                             data={"artifact": str(artifact.pk),
                                   "source": {
                                       "Type": "com.apple.configuration.passcode.settings",
                                       "Identifier": "com.example.ddm.1",
                                       "ServerToken": "8cbb059c-326a-4ad8-8ffc-ea6c72e368a1",
                                       "Payload": {"MinimumLength": 10},
                                   },
                                   "macos": True})
        self.assertEqual(response.status_code, 403)

    def test_create_declaration_type_error(self):
        artifact, (av,) = force_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        self.set_permissions("mdm.add_declaration")
        response = self.post(reverse("mdm_api:declarations"),
                             data={"artifact": str(artifact.pk),
                                   'source': {'Identifier': av.declaration.identifier,
                                              'ServerToken': "8cbb059c-326a-4ad8-8ffc-ea6c72e368a1",
                                              'Payload': {},
                                              'Type': 'com.apple.configuration.services.configuration-files'},
                                   "macos": True,
                                   "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'source': ['A declaration with a different Type exists for this artifact']}
        )

    def test_create_declaration_missing_server_token_error(self):
        artifact, (av,) = force_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        self.set_permissions("mdm.add_declaration")
        response = self.post(reverse("mdm_api:declarations"),
                             data={"artifact": str(artifact.pk),
                                   'source': {'Identifier': av.declaration.identifier,
                                              'Payload': {
                                                  'ExternalStorage': 'Allowed',
                                                  'NetworkStorage': 'Disallowed',
                                              },
                                              'Type': 'com.apple.configuration.diskmanagement.settings'},
                                   "macos": True,
                                   "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'source': ['Missing ServerToken']}
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_declaration(self, post_event):
        asset_artifact, _ = force_artifact(artifact_type=Artifact.Type.ASSET, decl_type="com.apple.asset.data")
        blueprint_artifact, artifact, _ = force_blueprint_artifact(
            artifact_type=Artifact.Type.CONFIGURATION,
            version_count=0,
        )
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 0)
        self.set_permissions("mdm.add_declaration")
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        identifier = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(reverse("mdm_api:declarations"),
                                 data={"artifact": str(artifact.pk),
                                       'source': {'Identifier': identifier,
                                                  'ServerToken': "8cbb059c-326a-4ad8-8ffc-ea6c72e368a1",
                                                  'Payload': {'ServiceType': 'sudo',
                                                              'DataAssetReference': f'ztl:{asset_artifact.pk}'},
                                                  'Type': 'com.apple.configuration.services.configuration-files'},
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
             'source': {
                 'Identifier': identifier,
                 'Payload': {'ServiceType': 'sudo',
                             'DataAssetReference': f'ztl:{asset_artifact.pk}'},
                 'Type': 'com.apple.configuration.services.configuration-files',
                 'ServerToken': '8cbb059c-326a-4ad8-8ffc-ea6c72e368a1',
             },
             'tag_shards': [{"tag": shard_tag.pk, "shard": 5}],
             'tvos': False,
             'tvos_max_version': '',
             'tvos_min_version': '',
             'version': 17,
             'created_at': av.created_at.isoformat(),
             'updated_at': av.updated_at.isoformat()}
        )
        self.assertEqual(av.declaration.declarationref_set.count(), 1)
        decl_ref = av.declaration.declarationref_set.first()
        self.assertEqual(decl_ref.key, ['DataAssetReference'])
        self.assertEqual(decl_ref.artifact, asset_artifact)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "mdm.declaration",
                 "pk": str(av.declaration.pk),
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
                     'shard_modulo': 10,
                     'source': {
                         'Identifier': av.declaration.identifier,
                         'Payload': {'ServiceType': 'sudo',
                                     'DataAssetReference': f'ztl:{asset_artifact.pk}'},
                         'Type': 'com.apple.configuration.services.configuration-files',
                         'ServerToken': av.declaration.server_token,
                     },
                     'tag_shards': [{"tag": {"pk": shard_tag.pk, "name": shard_tag.name}, "shard": 5}],
                     'tvos': False,
                     'tvos_max_version': '',
                     'tvos_min_version': '',
                     'version': 17,
                     "created_at": av.created_at,
                     "updated_at": av.updated_at
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_declaration": [str(av.declaration.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        blueprint.refresh_from_db()
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 1)

    # get declaration

    def test_get_declaration_unauthorized(self):
        artifact, (av,) = force_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        response = self.get(reverse("mdm_api:declaration", args=(av.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_declaration_permission_denied(self):
        artifact, (av,) = force_artifact()
        response = self.get(reverse("mdm_api:declaration", args=(av.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_declaration(self):
        force_artifact()
        artifact, (av,) = force_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        self.set_permissions("mdm.view_declaration")
        response = self.get(reverse("mdm_api:declaration", args=(av.pk,)))
        self.assertEqual(response.status_code, 200)
        data = response.json()
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
             'source': {
                 'Identifier': av.declaration.identifier,
                 'Payload': {'Restrictions': {'ExternalStorage': 'Disallowed',
                                              'NetworkStorage': 'Disallowed'}},
                 'ServerToken': av.declaration.server_token,
                 'Type': 'com.apple.configuration.diskmanagement.settings'
             },
             'tag_shards': [],
             'tvos': False,
             'tvos_max_version': '',
             'tvos_min_version': '',
             'version': av.version,
             'created_at': av.created_at.isoformat(),
             'updated_at': av.updated_at.isoformat()}
        )

    # update declaration

    def test_update_declaration_unauthorized(self):
        artifact, (av,) = force_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        response = self.put(reverse("mdm_api:declaration", args=(av.pk,)),
                            data={"artifact": str(artifact.pk),
                                  "source": {
                                      "Type": "com.apple.configuration.passcode.settings",
                                      "Identifier": "com.example.ddm.1",
                                      "ServerToken": "8cbb059c-326a-4ad8-8ffc-ea6c72e368a1",
                                      "Payload": {"MinimumLength": 10},
                                  },
                                  "macos": True,
                                  "version": 2},
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_declaration_permission_denied(self):
        artifact, (av,) = force_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        response = self.put(reverse("mdm_api:declaration", args=(av.pk,)),
                            data={"artifact": str(artifact.pk),
                                  "source": {
                                      "Type": "com.apple.configuration.passcode.settings",
                                      "Identifier": "com.example.ddm.1",
                                      "ServerToken": "8cbb059c-326a-4ad8-8ffc-ea6c72e368a1",
                                      "Payload": {"MinimumLength": 10},
                                  },
                                  "macos": True,
                                  "version": 2})
        self.assertEqual(response.status_code, 403)

    def test_update_declaration_identifier_error(self):
        artifact, (av,) = force_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        self.set_permissions("mdm.change_declaration")
        response = self.put(reverse("mdm_api:declaration", args=(av.pk,)),
                            data={"artifact": str(artifact.pk),
                                  "source": {
                                      "Type": av.declaration.type,
                                      "Identifier": "com.example.ddm.1",
                                      "ServerToken": "8cbb059c-326a-4ad8-8ffc-ea6c72e368a1",
                                      "Payload": {"yolo": "fomo"},
                                  },
                                  "macos": True,
                                  "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'source': ['A declaration with a different Identifier exists for this artifact']}
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_declaration(self, post_event):
        asset_artifact0, _ = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        asset_artifact1, _ = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        asset_artifact2, _ = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        blueprint_artifact, artifact, (av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.CONFIGURATION,
            decl_type="com.apple.configuration.services.configuration-files",
            decl_payload={
                "ServiceType": "com.apple.sudo",
                "DataAssetReference": f"ztl:{asset_artifact0.pk}",
                "DataAssetReference2": f"ztl:{asset_artifact1.pk}",
            },
        )
        decl_ref0 = DeclarationRef.objects.get(
            declaration=av.declaration,
            key=['DataAssetReference'],
            artifact=asset_artifact0
        )
        DeclarationRef.objects.create(
            declaration=av.declaration,
            key=['DataAssetReference2'],
            artifact=asset_artifact1
        )
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(blueprint.serialized_artifacts[str(artifact.pk)]["versions"][0]["excluded_tags"], [])
        av.excluded_tags.set([Tag.objects.create(name=get_random_string(12))])
        ArtifactVersionTag.objects.create(artifact_version=av,
                                          tag=Tag.objects.create(name=get_random_string(12)),
                                          shard=1)
        prev_value = av.declaration.serialize_for_event()
        self.set_permissions("mdm.change_declaration")
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(reverse("mdm_api:declaration", args=(av.pk,)),
                                data={"artifact": str(artifact.pk),
                                      'source': {'Identifier': av.declaration.identifier,
                                                 'ServerToken': '8cbb059c-326a-4ad8-8ffc-ea6c72e368a1',
                                                 'Type': 'com.apple.configuration.services.configuration-files',
                                                 'Payload': {'ServiceType': 'com.apple.sudo',
                                                             'DataAssetReference': f'ztl:{asset_artifact2.pk}'}},
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
             'source': {
                 'Identifier': av.declaration.identifier,
                 'Payload': {'ServiceType': 'com.apple.sudo',
                             'DataAssetReference': f'ztl:{asset_artifact2.pk}'},
                 'ServerToken': av.declaration.server_token,
                 'Type': 'com.apple.configuration.services.configuration-files',
             },
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
                 "model": "mdm.declaration",
                 "pk": str(av.declaration.pk),
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
                     'shard_modulo': 10,
                     'source': {
                         'Identifier': av.declaration.identifier,
                         'Payload': {'ServiceType': 'com.apple.sudo',
                                     'DataAssetReference': f'ztl:{asset_artifact2.pk}'},
                         'ServerToken': av.declaration.server_token,
                         'Type': 'com.apple.configuration.services.configuration-files',
                     },
                     'tag_shards': [{"tag": {"pk": shard_tag.pk, "name": shard_tag.name}, "shard": 5}],
                     'tvos': False,
                     'tvos_max_version': '',
                     'tvos_min_version': '',
                     'version': 17,
                     "created_at": av.created_at,
                     "updated_at": av.updated_at
                 },
                 "prev_value": prev_value,
              }}
        )
        self.assertEqual(av.declaration.declarationref_set.count(), 1)
        decl_ref2 = av.declaration.declarationref_set.first()
        self.assertEqual(decl_ref2, decl_ref0)
        self.assertEqual(decl_ref2.key, ['DataAssetReference'])
        self.assertEqual(decl_ref2.artifact, asset_artifact2)
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_declaration": [str(av.declaration.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        blueprint.refresh_from_db()
        self.assertEqual(blueprint.serialized_artifacts[str(artifact.pk)]["versions"][0]["excluded_tags"],
                         [excluded_tag.pk])

    # delete declaration

    def test_delete_declaration_unauthorized(self):
        artifact, (av,) = force_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        response = self.delete(reverse("mdm_api:declaration", args=(av.pk,)),
                               include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_declaration_permission_denied(self):
        artifact, (av,) = force_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        response = self.delete(reverse("mdm_api:declaration", args=(av.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_declaration_cannot_be_deleted(self):
        artifact, (av,) = force_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        session, _, _ = force_dep_enrollment_session(MetaBusinessUnit.objects.create(name=get_random_string(12)),
                                                     completed=True)
        DeviceArtifact.objects.create(
            enrolled_device=session.enrolled_device,
            artifact_version=av,
            status=TargetArtifact.Status.INSTALLED
        )
        self.set_permissions("mdm.delete_declaration")
        response = self.delete(reverse("mdm_api:declaration", args=(av.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ["This declaration cannot be deleted"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_declaration(self, post_event):
        blueprint_artifact, artifact, (av,) = force_blueprint_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 1)
        self.assertEqual(blueprint.serialized_artifacts[str(artifact.pk)]["versions"][0]["pk"],
                         str(av.pk))
        prev_value = av.declaration.serialize_for_event()
        self.set_permissions("mdm.delete_declaration")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("mdm_api:declaration", args=(av.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "mdm.declaration",
                 "pk": str(av.declaration.pk),
                 "prev_value": prev_value,
             }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_declaration": [str(av.declaration.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        self.assertEqual(ArtifactVersion.objects.filter(pk=av.pk).count(), 0)
        blueprint.refresh_from_db()
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 0)

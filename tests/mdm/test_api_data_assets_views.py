from functools import reduce
import hashlib
import io
import operator
import os
import tempfile
from unittest.mock import Mock, patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase
from accounts.models import APIToken, User
from zentral.contrib.inventory.models import MetaBusinessUnit, Tag
from zentral.contrib.mdm.models import Artifact, ArtifactVersion, ArtifactVersionTag, DeviceArtifact, TargetArtifact
from zentral.core.events.base import AuditEvent
from .utils import (build_plistfile, build_zipfile,
                    force_artifact, force_blueprint_artifact, force_dep_enrollment_session)


class MDMDataAssetsAPIViewsTestCase(TestCase):
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

    # list data assets

    def test_list_data_assets_unauthorized(self):
        response = self.get(reverse("mdm_api:data_assets"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_data_assets_permission_denied(self):
        response = self.get(reverse("mdm_api:data_assets"))
        self.assertEqual(response.status_code, 403)

    def test_list_data_assets(self):
        artifact, (ea_av,) = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        self.set_permissions("mdm.view_dataasset")
        response = self.get(reverse("mdm_api:data_assets"))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(
            data,
            [{'id': str(ea_av.pk),
              'artifact': str(artifact.pk),
              'default_shard': 100,
              'excluded_tags': [],
              'file_sha256': ea_av.data_asset.file_sha256,
              'file_size': ea_av.data_asset.file_size,
              'filename': ea_av.data_asset.filename,
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
              'type': 'ZIP',
              'version': ea_av.version,
              'created_at': ea_av.created_at.isoformat(),
              'updated_at': ea_av.updated_at.isoformat()}]
        )

    # create data asset

    def test_create_data_asset_unauthorized(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        response = self.post(reverse("mdm_api:data_assets"),
                             data={"artifact": str(artifact.pk),
                                   "type": "ZIP",
                                   "file_uri": "s3://yolo/fomo.zip",
                                   "file_sha256": 64 * "0",
                                   "macos": True,
                                   "version": 1},
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_data_asset_permission_denied(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        response = self.post(reverse("mdm_api:data_assets"),
                             data={"artifact": str(artifact.pk),
                                   "type": "ZIP",
                                   "file_uri": "s3://yolo/fomo.zip",
                                   "file_sha256": 64 * "0",
                                   "macos": True,
                                   "version": 1})
        self.assertEqual(response.status_code, 403)

    def test_create_data_asset_missing_fields_error(self):
        _, artifact, (ea_av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.DATA_ASSET
        )
        self.set_permissions("mdm.add_dataasset")
        response = self.post(reverse("mdm_api:data_assets"),
                             data={"artifact": str(artifact.pk),
                                   "macos": True,
                                   "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'file_sha256': ['This field is required.'],
             'file_uri': ['This field is required.'],
             'type': ['This field is required.']}
        )

    def test_create_data_asset_plist_type_sha_error(self):
        _, artifact, (ea_av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.DATA_ASSET
        )
        self.set_permissions("mdm.add_dataasset")
        response = self.post(reverse("mdm_api:data_assets"),
                             data={"artifact": str(artifact.pk),
                                   "type": "YOLO",
                                   "file_uri": "s3://yolo/fomo.zip",
                                   "file_sha256": "0",
                                   "macos": True,
                                   "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'file_sha256': ['This value does not match the required pattern.'],
             'type': ['"YOLO" is not a valid choice.']}
        )

    def test_create_data_asset_plist_file_extension_error(self):
        _, artifact, (ea_av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.DATA_ASSET
        )
        self.set_permissions("mdm.add_dataasset")
        response = self.post(reverse("mdm_api:data_assets"),
                             data={"artifact": str(artifact.pk),
                                   "type": "PLIST",
                                   "file_uri": "s3://yolo/fomo.zip",
                                   "file_sha256": 64 * "0",
                                   "macos": True,
                                   "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'file_uri': ["Unsupported file extension: '.zip'"]}
        )

    def test_create_data_asset_zip_file_extension_error(self):
        _, artifact, (ea_av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.DATA_ASSET
        )
        self.set_permissions("mdm.add_dataasset")
        response = self.post(reverse("mdm_api:data_assets"),
                             data={"artifact": str(artifact.pk),
                                   "type": "ZIP",
                                   "file_uri": "s3://yolo/fomo.plist",
                                   "file_sha256": 64 * "0",
                                   "macos": True,
                                   "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'file_uri': ["Unsupported file extension: '.plist'"]}
        )

    def test_create_data_asset_unknown_scheme(self):
        _, artifact, (ea_av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.DATA_ASSET
        )
        self.set_permissions("mdm.add_dataasset")
        response = self.post(reverse("mdm_api:data_assets"),
                             data={"artifact": str(artifact.pk),
                                   "type": "ZIP",
                                   "file_uri": "ftp://yolo/fomo.zip",
                                   "file_sha256": 64 * "0",
                                   "macos": True,
                                   "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'file_uri': ["Unknown external resource URI scheme: 'ftp'"]}
        )

    @patch("zentral.utils.external_resources.boto3.client")
    def test_create_data_asset_s3_error(self, boto3_client):
        boom = Mock()
        boom.download_fileobj.side_effect = ValueError("Boom!!!")
        boto3_client.return_value = boom
        _, artifact, _ = force_blueprint_artifact(
            artifact_type=Artifact.Type.DATA_ASSET
        )
        self.set_permissions("mdm.add_dataasset")
        with patch.dict(os.environ, {"AWS_REGION": "eu-central-17"}):
            response = self.post(reverse("mdm_api:data_assets"),
                                 data={"artifact": str(artifact.pk),
                                       "type": "ZIP",
                                       "file_uri": "s3://yolo/fomo.zip",
                                       "file_sha256": 64 * "0",
                                       "macos": True,
                                       "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'file_uri': ['Boom!!!']}
        )
        boto3_client.assert_called_once_with("s3", region_name="eu-central-17")
        boom.download_fileobj.assert_called_once()
        self.assertEqual(boom.download_fileobj.call_args[0][0], "yolo")
        self.assertEqual(boom.download_fileobj.call_args[0][1], "fomo.zip")

    @patch("zentral.utils.external_resources.download_s3_external_resource")
    def test_create_data_asset_hash_mismatch(self, download_s3_external_resource):
        _, artifact, _ = force_blueprint_artifact(
            artifact_type=Artifact.Type.DATA_ASSET
        )
        download_s3_external_resource.return_value = build_zipfile()
        self.set_permissions("mdm.add_dataasset")
        response = self.post(reverse("mdm_api:data_assets"),
                             data={"artifact": str(artifact.pk),
                                   "type": "ZIP",
                                   "file_uri": "s3://yolo/fomo.zip",
                                   "file_sha256": 64 * "0",
                                   "macos": True,
                                   "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'file_uri': ['Hash mismatch']}
        )

    @patch("zentral.utils.external_resources.download_s3_external_resource")
    def test_create_data_asset_same_file_error(self, download_s3_external_resource):
        _, artifact, (av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.DATA_ASSET
        )
        zipfile = build_zipfile()
        file_sha256 = hashlib.sha256(zipfile.getvalue()).hexdigest()
        av.data_asset.file_sha256 = file_sha256  # create conflict
        av.data_asset.save()
        download_s3_external_resource.return_value = zipfile
        self.set_permissions("mdm.add_dataasset")
        response = self.post(reverse("mdm_api:data_assets"),
                             data={"artifact": str(artifact.pk),
                                   "type": "ZIP",
                                   "file_uri": "s3://yolo/fomo.zip",
                                   "file_sha256": file_sha256,
                                   "macos": True,
                                   "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'file_uri': ['This file is not different from the latest one']}
        )

    @patch("zentral.utils.external_resources.download_s3_external_resource")
    def test_create_data_asset_invalid_zip_error(self, download_s3_external_resource):
        _, artifact, (av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.DATA_ASSET
        )
        with tempfile.NamedTemporaryFile(delete=False) as tmp_data_asset_file:
            zipfile = io.BytesIO(b"0123")
            zipfile.name = tmp_data_asset_file.name
            zipfile.seek(0)
            zipfile_content = zipfile.getvalue()
            tmp_data_asset_file.write(zipfile_content)
            tmp_data_asset_file.close()
        self.assertTrue(os.path.exists(tmp_data_asset_file.name))
        file_sha256 = hashlib.sha256(zipfile_content).hexdigest()
        download_s3_external_resource.return_value = zipfile
        self.set_permissions("mdm.add_dataasset")
        response = self.post(reverse("mdm_api:data_assets"),
                             data={"artifact": str(artifact.pk),
                                   "type": "ZIP",
                                   "file_uri": "s3://yolo/fomo.zip",
                                   "file_sha256": file_sha256,
                                   "macos": True,
                                   "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'file_uri': ['Invalid ZIP file']}
        )
        self.assertFalse(os.path.exists(tmp_data_asset_file.name))

    @patch("zentral.utils.external_resources.download_s3_external_resource")
    def test_create_data_asset_invalid_plist_error(self, download_s3_external_resource):
        _, artifact, (av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.DATA_ASSET
        )
        with tempfile.NamedTemporaryFile(delete=False) as tmp_data_asset_file:
            plistfile = io.BytesIO(b"\x00")
            plistfile.name = tmp_data_asset_file.name
            plistfile.seek(0)
            plistfile_content = plistfile.getvalue()
            tmp_data_asset_file.write(plistfile_content)
            tmp_data_asset_file.close()
        self.assertTrue(os.path.exists(tmp_data_asset_file.name))
        file_sha256 = hashlib.sha256(plistfile_content).hexdigest()
        download_s3_external_resource.return_value = plistfile
        self.set_permissions("mdm.add_dataasset")
        response = self.post(reverse("mdm_api:data_assets"),
                             data={"artifact": str(artifact.pk),
                                   "type": "PLIST",
                                   "file_uri": "s3://yolo/fomo.plist",
                                   "file_sha256": file_sha256,
                                   "macos": True,
                                   "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'file_uri': ['Invalid PLIST file']}
        )
        self.assertFalse(os.path.exists(tmp_data_asset_file.name))

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("zentral.utils.external_resources.download_s3_external_resource")
    def test_create_data_asset(self, download_s3_external_resource, post_event):
        with tempfile.NamedTemporaryFile(delete=False) as tmp_data_asset_file:
            zipfile = build_zipfile(filename=tmp_data_asset_file.name, random=True)
            zipfile_content = zipfile.getvalue()
            tmp_data_asset_file.write(zipfile_content)
            tmp_data_asset_file.close()
        self.assertTrue(os.path.exists(tmp_data_asset_file.name))
        file_sha256 = hashlib.sha256(zipfile_content).hexdigest()
        file_size = len(zipfile_content)
        download_s3_external_resource.return_value = zipfile
        blueprint_artifact, artifact, _ = force_blueprint_artifact(
            artifact_type=Artifact.Type.DATA_ASSET,
        )
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 1)
        self.set_permissions("mdm.add_dataasset")
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(reverse("mdm_api:data_assets"),
                                 data={"artifact": str(artifact.pk),
                                       "type": "ZIP",
                                       "file_uri": "s3://yolo/fomo.zip",
                                       "file_sha256": file_sha256,
                                       "macos": True,
                                       "macos_max_version": "",  # blank OK
                                       "macos_min_version": "13.3.1",
                                       "excluded_tags": [excluded_tag.pk],
                                       "shard_modulo": 10,
                                       "default_shard": 0,
                                       "tag_shards": [{"tag": shard_tag.pk, "shard": 5}],
                                       "version": 17})
        self.assertEqual(response.status_code, 201)
        self.assertFalse(os.path.exists(tmp_data_asset_file.name))
        self.assertEqual(len(callbacks), 1)
        data = response.json()
        ea_av = artifact.artifactversion_set.all().order_by("-created_at").first()
        self.assertEqual(
            data,
            {'id': str(ea_av.pk),
             'artifact': str(artifact.pk),
             'default_shard': 0,
             'excluded_tags': [excluded_tag.pk],
             'file_sha256': file_sha256,
             'file_size': file_size,
             'filename': 'fomo.zip',
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
             'type': 'ZIP',
             'version': 17,
             'created_at': ea_av.created_at.isoformat(),
             'updated_at': ea_av.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "mdm.dataasset",
                 "pk": str(ea_av.data_asset.pk),
                 "new_value": {
                     "pk": str(ea_av.pk),
                     "artifact": {"pk": str(artifact.pk), "name": artifact.name},
                     'default_shard': 0,
                     'excluded_tags': [{"pk": excluded_tag.pk, "name": excluded_tag.name}],
                     'file_sha256': file_sha256,
                     'file_size': file_size,
                     'filename': 'fomo.zip',
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
                     'type': 'ZIP',
                     'version': 17,
                     "created_at": ea_av.created_at,
                     "updated_at": ea_av.updated_at
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_data_asset": [str(ea_av.data_asset.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        blueprint.refresh_from_db()
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 2)

    # get data asset

    def test_get_data_asset_unauthorized(self):
        artifact, (ea_av,) = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        response = self.get(reverse("mdm_api:data_asset", args=(ea_av.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_data_asset_permission_denied(self):
        artifact, (ea_av,) = force_artifact()
        response = self.get(reverse("mdm_api:data_asset", args=(ea_av.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_artifact(self):
        force_artifact()
        artifact, (ea_av,) = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        self.set_permissions("mdm.view_dataasset")
        response = self.get(reverse("mdm_api:data_asset", args=(ea_av.pk,)))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(
            data,
            {'id': str(ea_av.pk),
             'artifact': str(artifact.pk),
             'default_shard': 100,
             'excluded_tags': [],
             'file_sha256': ea_av.data_asset.file_sha256,
             'file_size': ea_av.data_asset.file_size,
             'filename': ea_av.data_asset.filename,
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
             'type': 'ZIP',
             'version': ea_av.version,
             'created_at': ea_av.created_at.isoformat(),
             'updated_at': ea_av.updated_at.isoformat()}
        )

    # update data asset

    def test_update_data_asset_unauthorized(self):
        artifact, (ea_av,) = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        response = self.put(reverse("mdm_api:data_asset", args=(ea_av.pk,)),
                            data={"artifact": str(artifact.pk),
                                  "type": "ZIP",
                                  "file_uri": "s3://yolo/fomo.zip",
                                  "file_sha256": 64 * "0",
                                  "macos": True,
                                  "version": 1},
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_data_asset_permission_denied(self):
        artifact, (ea_av,) = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        response = self.put(reverse("mdm_api:data_asset", args=(ea_av.pk,)),
                            data={"artifact": str(artifact.pk),
                                  "type": "ZIP",
                                  "file_uri": "s3://yolo/fomo.zip",
                                  "file_sha256": 64 * "0",
                                  "macos": True,
                                  "version": 1})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("zentral.utils.external_resources.download_s3_external_resource")
    def test_update_data_asset(self, download_s3_external_resource, post_event):
        blueprint_artifact, artifact, (ea_av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.DATA_ASSET
        )
        with tempfile.NamedTemporaryFile(delete=False) as tmp_data_asset_file:
            plistfile = build_plistfile(filename=tmp_data_asset_file.name, random=True)
            plistfile_content = plistfile.getvalue()
            tmp_data_asset_file.write(plistfile_content)
            tmp_data_asset_file.close()
        self.assertTrue(os.path.exists(tmp_data_asset_file.name))
        file_sha256 = hashlib.sha256(plistfile_content).hexdigest()
        file_size = len(plistfile_content)
        download_s3_external_resource.return_value = plistfile
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(blueprint.serialized_artifacts[str(artifact.pk)]["versions"][0]["excluded_tags"], [])
        ea_av.excluded_tags.set([Tag.objects.create(name=get_random_string(12))])
        ea_av.data_asset.save()
        ArtifactVersionTag.objects.create(artifact_version=ea_av,
                                          tag=Tag.objects.create(name=get_random_string(12)),
                                          shard=1)
        prev_value = ea_av.data_asset.serialize_for_event()
        self.set_permissions("mdm.change_dataasset")
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(reverse("mdm_api:data_asset", args=(ea_av.pk,)),
                                data={"artifact": str(artifact.pk),
                                      "type": "PLIST",
                                      "file_uri": "s3://yolo/fomo.plist",
                                      "file_sha256": file_sha256,
                                      "macos": True,
                                      "macos_min_version": "13.3.1",
                                      "excluded_tags": [excluded_tag.pk],
                                      "shard_modulo": 10,
                                      "default_shard": 0,
                                      "tag_shards": [{"tag": shard_tag.pk, "shard": 5}],
                                      "version": 17})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(os.path.exists(tmp_data_asset_file.name))
        self.assertEqual(len(callbacks), 1)
        data = response.json()
        ea_av.refresh_from_db()
        self.assertEqual(
            data,
            {'id': str(ea_av.pk),
             'artifact': str(artifact.pk),
             'default_shard': 0,
             'excluded_tags': [excluded_tag.pk],
             'file_sha256': file_sha256,
             'file_size': file_size,
             'filename': "fomo.plist",
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
             'type': 'PLIST',
             'version': 17,
             'created_at': ea_av.created_at.isoformat(),
             'updated_at': ea_av.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "mdm.dataasset",
                 "pk": str(ea_av.data_asset.pk),
                 "new_value": {
                     "pk": str(ea_av.pk),
                     "artifact": {"pk": str(artifact.pk), "name": artifact.name},
                     'default_shard': 0,
                     'excluded_tags': [{"pk": excluded_tag.pk, "name": excluded_tag.name}],
                     'file_sha256': file_sha256,
                     'file_size': file_size,
                     'filename': "fomo.plist",
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
                     'type': 'PLIST',
                     'version': 17,
                     "created_at": ea_av.created_at,
                     "updated_at": ea_av.updated_at
                 },
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_data_asset": [str(ea_av.data_asset.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        blueprint.refresh_from_db()
        self.assertEqual(blueprint.serialized_artifacts[str(artifact.pk)]["versions"][0]["excluded_tags"],
                         [excluded_tag.pk])

    # delete data asset

    def test_delete_data_asset_unauthorized(self):
        artifact, (ea_av,) = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        response = self.delete(reverse("mdm_api:data_asset", args=(ea_av.pk,)),
                               include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_data_asset_permission_denied(self):
        artifact, (ea_av,) = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        response = self.delete(reverse("mdm_api:data_asset", args=(ea_av.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_data_asset_cannot_be_deleted(self):
        artifact, (ea_av,) = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        session, _, _ = force_dep_enrollment_session(MetaBusinessUnit.objects.create(name=get_random_string(12)),
                                                     completed=True)
        DeviceArtifact.objects.create(
            enrolled_device=session.enrolled_device,
            artifact_version=ea_av,
            status=TargetArtifact.Status.INSTALLED
        )
        self.set_permissions("mdm.delete_dataasset")
        response = self.delete(reverse("mdm_api:data_asset", args=(ea_av.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ["This data asset cannot be deleted"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_data_asset(self, post_event):
        blueprint_artifact, artifact, (ea_av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.DATA_ASSET
        )
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 1)
        self.assertEqual(blueprint.serialized_artifacts[str(artifact.pk)]["versions"][0]["pk"],
                         str(ea_av.pk))
        prev_value = ea_av.data_asset.serialize_for_event()
        self.set_permissions("mdm.delete_dataasset")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("mdm_api:data_asset", args=(ea_av.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "mdm.dataasset",
                 "pk": str(ea_av.data_asset.pk),
                 "prev_value": prev_value,
             }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_data_asset": [str(ea_av.data_asset.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        self.assertEqual(ArtifactVersion.objects.filter(pk=ea_av.pk).count(), 0)
        blueprint.refresh_from_db()
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 0)

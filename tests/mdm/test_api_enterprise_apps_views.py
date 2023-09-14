from functools import lru_cache, reduce
import hashlib
import operator
import os
import tempfile
from unittest.mock import Mock, patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from accounts.models import APIToken, User
from zentral.contrib.inventory.models import MetaBusinessUnit, Tag
from zentral.contrib.mdm.models import Artifact, ArtifactVersion, ArtifactVersionTag, DeviceArtifact, TargetArtifact
from zentral.core.events.base import AuditEvent
from utils.packages import build_dummy_package
from .utils import force_artifact, force_blueprint_artifact, force_dep_enrollment_session


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MDMEnterpriseAppsAPIViewsTestCase(TestCase):
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
        cls.api_key = APIToken.objects.update_or_create_for_user(cls.service_account)

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

    @lru_cache
    def _build_package(self, name="test123", version="1.0", product_archive=True):
        kwargs = {"name": name, "version": version}
        if product_archive:
            kwargs["product_archive_title"] = name
        file = tempfile.NamedTemporaryFile(suffix=".pkg", delete=False)
        content = build_dummy_package(**kwargs)
        file.write(content)
        sha256 = hashlib.sha256(content).hexdigest()
        md5 = hashlib.md5(content).hexdigest()
        return file, sha256, md5, len(content)

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

    # list enterprise apps

    def test_list_enterprise_apps_unauthorized(self):
        response = self.get(reverse("mdm_api:enterprise_apps"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_enterprise_apps_permission_denied(self):
        response = self.get(reverse("mdm_api:enterprise_apps"))
        self.assertEqual(response.status_code, 403)

    def test_list_enterprise_apps(self):
        artifact, (ea_av,) = force_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP)
        self.set_permissions("mdm.view_enterpriseapp")
        response = self.get(reverse("mdm_api:enterprise_apps"))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(
            data,
            [{'id': str(ea_av.pk),
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
              'version': ea_av.version,
              'bundles': [],
              'manifest': {'items': [{'assets': [{}]}]},
              'configuration': None,
              'filename': ea_av.enterprise_app.filename,
              'install_as_managed': False,
              'ios_app': False,
              'product_id': ea_av.enterprise_app.product_id,
              'product_version': ea_av.enterprise_app.product_version,
              'remove_on_unenroll': False,
              'created_at': ea_av.created_at.isoformat(),
              'updated_at': ea_av.updated_at.isoformat()}]
        )

    # create enterprise app

    def test_create_enterprise_app_unauthorized(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP)
        response = self.post(reverse("mdm_api:enterprise_apps"),
                             data={"artifact": str(artifact.pk),
                                   "source_uri": "s3://yolo/fomo.pkg",
                                   "source_sha256": 40 * "0",
                                   "macos": True},
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_enterprise_app_permission_denied(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP)
        response = self.post(reverse("mdm_api:enterprise_apps"),
                             data={"artifact": str(artifact.pk),
                                   "source_uri": "s3://yolo/fomo.pkg",
                                   "source_sha256": 40 * "0",
                                   "macos": True})
        self.assertEqual(response.status_code, 403)

    def test_create_enterprise_app_remove_on_unenroll_error(self):
        _, artifact, (ea_av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.ENTERPRISE_APP
        )
        ea_av.enterprise_app.product_id = "io.zentral.test123"  # make sure this is the same product_id
        ea_av.enterprise_app.save()
        self.set_permissions("mdm.add_enterpriseapp")
        response = self.post(reverse("mdm_api:enterprise_apps"),
                             data={"artifact": str(artifact.pk),
                                   "source_uri": "s3://yolo/fomo.pkg",
                                   "source_sha256": 40 * "0",
                                   "macos": True,
                                   "install_as_managed": False,
                                   "remove_on_unenroll": True,  # requires install_as_managed == True
                                   "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'remove_on_unenroll': ['Only available if installed as managed is also set']}
        )

    def test_create_enterprise_app_invalid_configuration(self):
        _, artifact, (ea_av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.ENTERPRISE_APP
        )
        ea_av.enterprise_app.product_id = "io.zentral.test123"  # make sure this is the same product_id
        ea_av.enterprise_app.save()
        self.set_permissions("mdm.add_enterpriseapp")
        response = self.post(reverse("mdm_api:enterprise_apps"),
                             data={"artifact": str(artifact.pk),
                                   "source_uri": "s3://yolo/fomo.pkg",
                                   "source_sha256": 40 * "0",
                                   "macos": True,
                                   "configuration": "well well well",
                                   "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'configuration': ['Invalid property list']}
        )

    def test_create_enterprise_app_unknown_scheme(self):
        _, artifact, (ea_av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.ENTERPRISE_APP
        )
        ea_av.enterprise_app.product_id = "io.zentral.test123"  # make sure this is the same product_id
        ea_av.enterprise_app.save()
        self.set_permissions("mdm.add_enterpriseapp")
        response = self.post(reverse("mdm_api:enterprise_apps"),
                             data={"artifact": str(artifact.pk),
                                   "source_uri": "ftp://yolo/fomo.pkg",
                                   "source_sha256": 40 * "0",
                                   "macos": True,
                                   "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'source_uri': ["Unknown source URI scheme: 'ftp'"]}
        )

    def test_create_enterprise_app_unsupported_file_extension(self):
        _, artifact, (ea_av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.ENTERPRISE_APP
        )
        ea_av.enterprise_app.product_id = "io.zentral.test123"  # make sure this is the same product_id
        ea_av.enterprise_app.save()
        self.set_permissions("mdm.add_enterpriseapp")
        response = self.post(reverse("mdm_api:enterprise_apps"),
                             data={"artifact": str(artifact.pk),
                                   "source_uri": "s3://yolo/fomo.dmg",
                                   "source_sha256": 40 * "0",
                                   "macos": True,
                                   "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'source_uri': ["Unsupported file extension: '.dmg'"]}
        )

    @patch("zentral.contrib.mdm.app_manifest.boto3.client")
    def test_create_enterprise_app_s3_error(self, boto3_client):
        boom = Mock()
        boom.download_fileobj.side_effect = ValueError("Boom!!!")
        boto3_client.return_value = boom
        _, artifact, _ = force_blueprint_artifact(
            artifact_type=Artifact.Type.ENTERPRISE_APP
        )
        self.set_permissions("mdm.add_enterpriseapp")
        with patch.dict(os.environ, {"AWS_REGION": "eu-central-17"}):
            response = self.post(reverse("mdm_api:enterprise_apps"),
                                 data={"artifact": str(artifact.pk),
                                       "source_uri": "s3://yolo/fomo.pkg",
                                       "source_sha256": 40 * "0",
                                       "macos": True,
                                       "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'source_uri': ['Boom!!!']}
        )
        boto3_client.assert_called_once_with("s3", region_name="eu-central-17")
        boom.download_fileobj.assert_called_once()
        self.assertEqual(boom.download_fileobj.call_args[0][0], "yolo")
        self.assertEqual(boom.download_fileobj.call_args[0][1], "fomo.pkg")

    @patch("zentral.contrib.mdm.app_manifest.download_s3_source")
    def test_create_enterprise_app_hash_mismatch(self, download_s3_source):
        _, artifact, _ = force_blueprint_artifact(
            artifact_type=Artifact.Type.ENTERPRISE_APP
        )
        package, _, _, _ = self._build_package()
        download_s3_source.return_value = package
        self.set_permissions("mdm.add_enterpriseapp")
        response = self.post(reverse("mdm_api:enterprise_apps"),
                             data={"artifact": str(artifact.pk),
                                   "source_uri": "s3://yolo/fomo.pkg",
                                   "source_sha256": 40 * "0",
                                   "macos": True,
                                   "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'source_uri': ['Hash mismatch']}
        )

    @patch("zentral.contrib.mdm.app_manifest.download_s3_source")
    def test_create_enterprise_app_different_product_id(self, download_s3_source):
        _, artifact, _ = force_blueprint_artifact(
            artifact_type=Artifact.Type.ENTERPRISE_APP
        )
        package, package_sha256, _, _ = self._build_package()
        download_s3_source.return_value = package
        self.set_permissions("mdm.add_enterpriseapp")
        response = self.post(reverse("mdm_api:enterprise_apps"),
                             data={"artifact": str(artifact.pk),
                                   "source_uri": "s3://yolo/fomo.pkg",
                                   "source_sha256": package_sha256,
                                   "macos": True,
                                   "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'source_uri': ['The product ID of the new app is not identical to the product ID of the other versions']}
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("zentral.contrib.mdm.app_manifest.download_s3_source")
    def test_create_enterprise_app(self, download_s3_source, post_event):
        package, package_sha256, package_md5, package_size = self._build_package()
        download_s3_source.return_value = package
        blueprint_artifact, artifact, (ea_av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.ENTERPRISE_APP
        )
        ea_av.enterprise_app.product_id = "io.zentral.test123"  # make sure this is the same product_id
        ea_av.enterprise_app.save()
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 1)
        self.set_permissions("mdm.add_enterpriseapp")
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(reverse("mdm_api:enterprise_apps"),
                                 data={"artifact": str(artifact.pk),
                                       "source_uri": "s3://yolo/fomo.pkg",
                                       "source_sha256": package_sha256,
                                       "macos": True,
                                       "macos_max_version": "",  # blank OK
                                       "macos_min_version": "13.3.1",
                                       "excluded_tags": [excluded_tag.pk],
                                       "shard_modulo": 10,
                                       "default_shard": 0,
                                       "tag_shards": [{"tag": shard_tag.pk, "shard": 5}],
                                       "version": 17,
                                       "configuration": "<dict><key>un</key><integer>1</integer></dict>"})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        data = response.json()
        ea_av = artifact.artifactversion_set.all().order_by("-created_at").first()
        self.assertEqual(
            data,
            {'id': str(ea_av.pk),
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
             'filename': "fomo.pkg",
             'product_id': "io.zentral.test123",
             'product_version': '1.0',
             'bundles': [],
             'manifest': {'items': [{'assets': [{'kind': 'software-package',
                                                 'md5-size': package_size,
                                                 'md5s': [package_md5]}]}]},
             'configuration': '<?xml version="1.0" encoding="UTF-8"?>\n'
                              '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                              '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
                              '<plist version="1.0">\n'
                              '<dict>\n\t'
                              '<key>un</key>\n\t'
                              '<integer>1</integer>\n'
                              '</dict>\n'
                              '</plist>\n',
             'install_as_managed': False,
             'ios_app': False,
             'remove_on_unenroll': False,
             'created_at': ea_av.created_at.isoformat(),
             'updated_at': ea_av.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "mdm.enterpriseapp",
                 "pk": str(ea_av.enterprise_app.pk),
                 "new_value": {
                     "pk": str(ea_av.pk),
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
                     'filename': 'fomo.pkg',
                     'product_id': "io.zentral.test123",
                     'product_version': "1.0",
                     'bundles': [],
                     'manifest': {'items': [{'assets': [{'kind': 'software-package',
                                                         'md5-size': package_size,
                                                         'md5s': [package_md5]}]}]},
                     'install_as_managed': False,
                     'remove_on_unenroll': False,
                     'ios_app': False,
                     'configuration': '<?xml version="1.0" encoding="UTF-8"?>\n'
                                      '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                                      '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
                                      '<plist version="1.0">\n'
                                      '<dict>\n\t'
                                      '<key>un</key>\n\t'
                                      '<integer>1</integer>\n'
                                      '</dict>\n'
                                      '</plist>\n',
                     "created_at": ea_av.created_at,
                     "updated_at": ea_av.updated_at
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_enterprise_app": [str(ea_av.enterprise_app.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        blueprint.refresh_from_db()
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 2)

    # get enterprise app

    def test_get_enterprise_app_unauthorized(self):
        artifact, (ea_av,) = force_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP)
        response = self.get(reverse("mdm_api:enterprise_app", args=(ea_av.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enterprise_app_permission_denied(self):
        artifact, (ea_av,) = force_artifact()
        response = self.get(reverse("mdm_api:enterprise_app", args=(ea_av.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_artifact(self):
        force_artifact()
        artifact, (ea_av,) = force_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP)
        self.set_permissions("mdm.view_enterpriseapp")
        response = self.get(reverse("mdm_api:enterprise_app", args=(ea_av.pk,)))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(
            data,
            {'id': str(ea_av.pk),
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
             'version': ea_av.version,
             'bundles': [],
             'manifest': {'items': [{'assets': [{}]}]},
             'configuration': None,
             'filename': ea_av.enterprise_app.filename,
             'install_as_managed': False,
             'ios_app': False,
             'product_id': ea_av.enterprise_app.product_id,
             'product_version': ea_av.enterprise_app.product_version,
             'remove_on_unenroll': False,
             'created_at': ea_av.created_at.isoformat(),
             'updated_at': ea_av.updated_at.isoformat()}
        )

    # update enterprise app

    def test_update_enterprise_app_unauthorized(self):
        artifact, (ea_av,) = force_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP)
        response = self.put(reverse("mdm_api:enterprise_app", args=(ea_av.pk,)),
                            data={"artifact": str(artifact.pk),
                                  "source_uri": "s3://yolo/fomo.pkg",
                                  "source_sha256": 40 * "0",
                                  "macos": True},
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_enterprise_app_permission_denied(self):
        artifact, (ea_av,) = force_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP)
        response = self.put(reverse("mdm_api:enterprise_app", args=(ea_av.pk,)),
                            data={"artifact": str(artifact.pk),
                                  "source_uri": "s3://yolo/fomo.pkg",
                                  "source_sha256": 40 * "0",
                                  "macos": True})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("zentral.contrib.mdm.app_manifest.download_s3_source")
    def test_update_enterprise_app(self, download_s3_source, post_event):
        blueprint_artifact, artifact, (ea_av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.ENTERPRISE_APP
        )
        package, package_sha256, package_md5, package_size = self._build_package()
        download_s3_source.return_value = package
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(blueprint.serialized_artifacts[str(artifact.pk)]["versions"][0]["excluded_tags"], [])
        ea_av.excluded_tags.set([Tag.objects.create(name=get_random_string(12))])
        ea_av.enterprise_app.product_id = "io.zentral.test123"  # make sure this is the same product_id
        ea_av.enterprise_app.save()
        ArtifactVersionTag.objects.create(artifact_version=ea_av,
                                          tag=Tag.objects.create(name=get_random_string(12)),
                                          shard=1)
        prev_value = ea_av.enterprise_app.serialize_for_event()
        self.set_permissions("mdm.change_enterpriseapp")
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(reverse("mdm_api:enterprise_app", args=(ea_av.pk,)),
                                data={"artifact": str(artifact.pk),
                                      "source_uri": "s3://yolo/fomo.pkg",
                                      "source_sha256": package_sha256,
                                      "macos": True,
                                      "macos_min_version": "13.3.1",
                                      "excluded_tags": [excluded_tag.pk],
                                      "shard_modulo": 10,
                                      "default_shard": 0,
                                      "tag_shards": [{"tag": shard_tag.pk, "shard": 5}],
                                      "configuration": None,
                                      "install_as_managed": True,
                                      "remove_on_unenroll": True,
                                      "version": 17})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        data = response.json()
        ea_av.refresh_from_db()
        self.assertEqual(
            data,
            {'id': str(ea_av.pk),
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
             'configuration': None,
             'filename': 'fomo.pkg',
             'install_as_managed': True,
             'ios_app': False,
             'product_id': 'io.zentral.test123',
             'product_version': '1.0',
             'bundles': [],
             'manifest': {'items': [{'assets': [{'kind': 'software-package',
                                                 'md5-size': package_size,
                                                 'md5s': [package_md5]}]}]},
             'remove_on_unenroll': True,
             'created_at': ea_av.created_at.isoformat(),
             'updated_at': ea_av.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "mdm.enterpriseapp",
                 "pk": str(ea_av.enterprise_app.pk),
                 "new_value": {
                     "pk": str(ea_av.pk),
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
                     'filename': 'fomo.pkg',
                     'product_id': "io.zentral.test123",
                     'product_version': "1.0",
                     'bundles': [],
                     'manifest': {'items': [{'assets': [{'kind': 'software-package',
                                                         'md5-size': package_size,
                                                         'md5s': [package_md5]}]}]},
                     'install_as_managed': True,
                     'remove_on_unenroll': True,
                     'ios_app': False,
                     "created_at": ea_av.created_at,
                     "updated_at": ea_av.updated_at
                 },
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_enterprise_app": [str(ea_av.enterprise_app.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        blueprint.refresh_from_db()
        self.assertEqual(blueprint.serialized_artifacts[str(artifact.pk)]["versions"][0]["excluded_tags"],
                         [excluded_tag.pk])

    # delete enterprise app

    def test_delete_enterprise_app_unauthorized(self):
        artifact, (ea_av,) = force_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP)
        response = self.delete(reverse("mdm_api:enterprise_app", args=(ea_av.pk,)),
                               include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_enterprise_app_permission_denied(self):
        artifact, (ea_av,) = force_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP)
        response = self.delete(reverse("mdm_api:enterprise_app", args=(ea_av.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_enterprise_app_cannot_be_deleted(self):
        artifact, (ea_av,) = force_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP)
        session, _, _ = force_dep_enrollment_session(MetaBusinessUnit.objects.create(name=get_random_string(12)),
                                                     completed=True)
        DeviceArtifact.objects.create(
            enrolled_device=session.enrolled_device,
            artifact_version=ea_av,
            status=TargetArtifact.Status.INSTALLED
        )
        self.set_permissions("mdm.delete_enterpriseapp")
        response = self.delete(reverse("mdm_api:enterprise_app", args=(ea_av.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ["This enterprise app cannot be deleted"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_enterprise_app(self, post_event):
        blueprint_artifact, artifact, (ea_av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.ENTERPRISE_APP
        )
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 1)
        self.assertEqual(blueprint.serialized_artifacts[str(artifact.pk)]["versions"][0]["pk"],
                         str(ea_av.pk))
        prev_value = ea_av.enterprise_app.serialize_for_event()
        self.set_permissions("mdm.delete_enterpriseapp")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("mdm_api:enterprise_app", args=(ea_av.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "mdm.enterpriseapp",
                 "pk": str(ea_av.enterprise_app.pk),
                 "prev_value": prev_value,
             }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_enterprise_app": [str(ea_av.enterprise_app.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        self.assertEqual(ArtifactVersion.objects.filter(pk=ea_av.pk).count(), 0)
        blueprint.refresh_from_db()
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 0)

from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from accounts.models import APIToken, User
from zentral.contrib.inventory.models import MetaBusinessUnit, Tag
from zentral.contrib.mdm.models import Artifact, ArtifactVersion, ArtifactVersionTag, DeviceArtifact, TargetArtifact
from zentral.core.events.base import AuditEvent
from .utils import force_artifact, force_blueprint_artifact, force_dep_enrollment_session, force_location_asset


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MDMStoreAppsAPIViewsTestCase(TestCase):
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

    # list store apps

    def test_list_store_apps_unauthorized(self):
        response = self.get(reverse("mdm_api:store_apps"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_store_apps_permission_denied(self):
        response = self.get(reverse("mdm_api:store_apps"))
        self.assertEqual(response.status_code, 403)

    def test_list_store_apps(self):
        artifact, (sa_av,) = force_artifact(artifact_type=Artifact.Type.STORE_APP)
        self.set_permissions("mdm.view_storeapp")
        response = self.get(reverse("mdm_api:store_apps"))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(
            data,
            [{'id': str(sa_av.pk),
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
              'version': sa_av.version,
              'location_asset': sa_av.store_app.location_asset.pk,
              'associated_domains': [],
              'associated_domains_enable_direct_downloads': False,
              'prevent_backup': False,
              'removable': False,
              'configuration': None,
              'remove_on_unenroll': True,
              'content_filter_uuid': None,
              'dns_proxy_uuid': None,
              'vpn_uuid': None,
              'created_at': sa_av.created_at.isoformat(),
              'updated_at': sa_av.updated_at.isoformat()}]
        )

    # create store app

    def test_create_store_app_unauthorized(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.STORE_APP)
        la = force_location_asset()
        response = self.post(reverse("mdm_api:store_apps"),
                             data={"artifact": str(artifact.pk),
                                   "location_asset": la.pk,
                                   "macos": True},
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_store_app_permission_denied(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.STORE_APP)
        la = force_location_asset()
        response = self.post(reverse("mdm_api:store_apps"),
                             data={"artifact": str(artifact.pk),
                                   "location_asset": la.pk,
                                   "macos": True})
        self.assertEqual(response.status_code, 403)

    def test_create_store_app_missing_fields(self):
        _, artifact, (sa_av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.STORE_APP
        )
        self.set_permissions("mdm.add_storeapp")
        response = self.post(reverse("mdm_api:store_apps"),
                             data={"artifact": str(artifact.pk),
                                   "macos": True,
                                   "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'location_asset': ['This field is required.']},
        )

    def test_create_store_app_invalid_configuration(self):
        _, artifact, (sa_av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.STORE_APP
        )
        self.set_permissions("mdm.add_storeapp")
        response = self.post(reverse("mdm_api:store_apps"),
                             data={"artifact": str(artifact.pk),
                                   "location_asset": sa_av.store_app.location_asset.pk,
                                   "macos": True,
                                   "configuration": "well well well",
                                   "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'configuration': ['Invalid property list']}
        )

    def test_create_store_app_different_product_id(self):
        _, artifact, _ = force_blueprint_artifact(
            artifact_type=Artifact.Type.STORE_APP
        )
        la = force_location_asset()
        self.set_permissions("mdm.add_storeapp")
        response = self.post(reverse("mdm_api:store_apps"),
                             data={"artifact": str(artifact.pk),
                                   "location_asset": la.pk,
                                   "macos": True,
                                   "version": 2})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'location_asset': ['The location asset of the new store app is not identical '
                                'to the location asset of the other versions']}
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_store_app(self, post_event):
        blueprint_artifact, artifact, (sa_av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.STORE_APP
        )
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 1)
        self.set_permissions("mdm.add_storeapp")
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        location_asset = sa_av.store_app.location_asset
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(reverse("mdm_api:store_apps"),
                                 data={"artifact": str(artifact.pk),
                                       "location_asset": location_asset.pk,
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
        sa_av = artifact.artifactversion_set.all().order_by("-created_at").first()
        self.assertEqual(
            data,
            {'id': str(sa_av.pk),
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
             'location_asset': location_asset.pk,
             'associated_domains': [],
             'associated_domains_enable_direct_downloads': False,
             'prevent_backup': False,
             'removable': False,
             'configuration': '<?xml version="1.0" encoding="UTF-8"?>\n'
                              '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                              '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
                              '<plist version="1.0">\n'
                              '<dict>\n\t'
                              '<key>un</key>\n\t'
                              '<integer>1</integer>\n'
                              '</dict>\n'
                              '</plist>\n',
             'content_filter_uuid': None,
             'dns_proxy_uuid': None,
             'vpn_uuid': None,
             'remove_on_unenroll': True,
             'created_at': sa_av.created_at.isoformat(),
             'updated_at': sa_av.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "mdm.storeapp",
                 "pk": str(sa_av.store_app.pk),
                 "new_value": {
                     "pk": str(sa_av.pk),
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
                     'remove_on_unenroll': True,
                     'location_asset': {
                         'asset': {
                             'adam_id': location_asset.asset.adam_id,
                             'pk': location_asset.asset.pk,
                             'pricing_param': location_asset.asset.pricing_param,
                         },
                         'location': {
                             'mdm_info_id': str(location_asset.location.mdm_info_id),
                             'pk': location_asset.location.pk,
                         }
                     },
                     'associated_domains': [],
                     'associated_domains_enable_direct_downloads': False,
                     'prevent_backup': False,
                     'removable': False,
                     'remove_on_unenroll': True,
                     'configuration': '<?xml version="1.0" encoding="UTF-8"?>\n'
                                      '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                                      '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
                                      '<plist version="1.0">\n'
                                      '<dict>\n\t'
                                      '<key>un</key>\n\t'
                                      '<integer>1</integer>\n'
                                      '</dict>\n'
                                      '</plist>\n',
                     "created_at": sa_av.created_at,
                     "updated_at": sa_av.updated_at
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_store_app": [str(sa_av.store_app.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        blueprint.refresh_from_db()
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 2)

    # get store app

    def test_get_store_app_unauthorized(self):
        artifact, (sa_av,) = force_artifact(artifact_type=Artifact.Type.STORE_APP)
        response = self.get(reverse("mdm_api:store_app", args=(sa_av.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_store_app_permission_denied(self):
        artifact, (sa_av,) = force_artifact()
        response = self.get(reverse("mdm_api:store_app", args=(sa_av.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_artifact(self):
        force_artifact()
        artifact, (sa_av,) = force_artifact(artifact_type=Artifact.Type.STORE_APP)
        self.set_permissions("mdm.view_storeapp")
        response = self.get(reverse("mdm_api:store_app", args=(sa_av.pk,)))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(
            data,
            {'id': str(sa_av.pk),
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
             'version': sa_av.version,
             'location_asset': sa_av.store_app.location_asset.pk,
             'associated_domains': [],
             'associated_domains_enable_direct_downloads': False,
             'prevent_backup': False,
             'removable': False,
             'configuration': None,
             'remove_on_unenroll': True,
             'content_filter_uuid': None,
             'dns_proxy_uuid': None,
             'vpn_uuid': None,
             'created_at': sa_av.created_at.isoformat(),
             'updated_at': sa_av.updated_at.isoformat()}
        )

    # update store app

    def test_update_store_app_unauthorized(self):
        artifact, (sa_av,) = force_artifact(artifact_type=Artifact.Type.STORE_APP)
        response = self.put(reverse("mdm_api:store_app", args=(sa_av.pk,)),
                            data={"artifact": str(artifact.pk),
                                  "location_asset": sa_av.store_app.location_asset.pk,
                                  "macos": True},
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_store_app_permission_denied(self):
        artifact, (sa_av,) = force_artifact(artifact_type=Artifact.Type.STORE_APP)
        response = self.put(reverse("mdm_api:store_app", args=(sa_av.pk,)),
                            data={"artifact": str(artifact.pk),
                                  "location_asset": sa_av.store_app.location_asset.pk,
                                  "macos": True})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_store_app(self, post_event):
        blueprint_artifact, artifact, (sa_av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.STORE_APP
        )
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(blueprint.serialized_artifacts[str(artifact.pk)]["versions"][0]["excluded_tags"], [])
        sa_av.excluded_tags.set([Tag.objects.create(name=get_random_string(12))])
        ArtifactVersionTag.objects.create(artifact_version=sa_av,
                                          tag=Tag.objects.create(name=get_random_string(12)),
                                          shard=1)
        prev_value = sa_av.store_app.serialize_for_event()
        self.set_permissions("mdm.change_storeapp")
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        location_asset = sa_av.store_app.location_asset
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(reverse("mdm_api:store_app", args=(sa_av.pk,)),
                                data={"artifact": str(artifact.pk),
                                      "location_asset": location_asset.pk,
                                      "macos": True,
                                      "macos_min_version": "13.3.1",
                                      "excluded_tags": [excluded_tag.pk],
                                      "shard_modulo": 10,
                                      "default_shard": 0,
                                      "tag_shards": [{"tag": shard_tag.pk, "shard": 5}],
                                      "configuration": None,
                                      "associated_domains": ["www.example.com"],
                                      "associated_domains_enable_direct_downloads": True,
                                      "content_filter_uuid": "123",
                                      "dns_proxy_uuid": "456",
                                      "vpn_uuid": "789",
                                      "removable": True,
                                      "remove_on_unenroll": False,
                                      "prevent_backup": True,
                                      "version": 17})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        data = response.json()
        sa_av.refresh_from_db()
        self.assertEqual(
            data,
            {'id': str(sa_av.pk),
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
             'location_asset': location_asset.pk,
             'associated_domains': ["www.example.com"],
             'associated_domains_enable_direct_downloads': True,
             'content_filter_uuid': "123",
             'dns_proxy_uuid': "456",
             'vpn_uuid': "789",
             'prevent_backup': True,
             'configuration': None,
             'removable': True,
             'remove_on_unenroll': False,
             'created_at': sa_av.created_at.isoformat(),
             'updated_at': sa_av.updated_at.isoformat()}
        )
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "mdm.storeapp",
                 "pk": str(sa_av.store_app.pk),
                 "new_value": {
                     "pk": str(sa_av.pk),
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
                     'location_asset': {
                         'asset': {
                             'adam_id': location_asset.asset.adam_id,
                             'pk': location_asset.asset.pk,
                             'pricing_param': location_asset.asset.pricing_param,
                         },
                         'location': {
                             'mdm_info_id': str(location_asset.location.mdm_info_id),
                             'pk': location_asset.location.pk,
                         }
                     },
                     'associated_domains': ["www.example.com"],
                     'associated_domains_enable_direct_downloads': True,
                     'content_filter_uuid': '123',
                     'dns_proxy_uuid': '456',
                     'vpn_uuid': '789',
                     'prevent_backup': True,
                     'removable': True,
                     'remove_on_unenroll': False,
                     "created_at": sa_av.created_at,
                     "updated_at": sa_av.updated_at
                 },
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_store_app": [str(sa_av.store_app.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        blueprint.refresh_from_db()
        self.assertEqual(blueprint.serialized_artifacts[str(artifact.pk)]["versions"][0]["excluded_tags"],
                         [excluded_tag.pk])

    # delete store app

    def test_delete_store_app_unauthorized(self):
        artifact, (sa_av,) = force_artifact(artifact_type=Artifact.Type.STORE_APP)
        response = self.delete(reverse("mdm_api:store_app", args=(sa_av.pk,)),
                               include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_store_app_permission_denied(self):
        artifact, (sa_av,) = force_artifact(artifact_type=Artifact.Type.STORE_APP)
        response = self.delete(reverse("mdm_api:store_app", args=(sa_av.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_store_app_cannot_be_deleted(self):
        artifact, (sa_av,) = force_artifact(artifact_type=Artifact.Type.STORE_APP)
        session, _, _ = force_dep_enrollment_session(MetaBusinessUnit.objects.create(name=get_random_string(12)),
                                                     completed=True)
        DeviceArtifact.objects.create(
            enrolled_device=session.enrolled_device,
            artifact_version=sa_av,
            status=TargetArtifact.Status.INSTALLED
        )
        self.set_permissions("mdm.delete_storeapp")
        response = self.delete(reverse("mdm_api:store_app", args=(sa_av.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ["This store app cannot be deleted"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_store_app(self, post_event):
        blueprint_artifact, artifact, (sa_av,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.STORE_APP
        )
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 1)
        self.assertEqual(blueprint.serialized_artifacts[str(artifact.pk)]["versions"][0]["pk"],
                         str(sa_av.pk))
        prev_value = sa_av.store_app.serialize_for_event()
        self.set_permissions("mdm.delete_storeapp")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("mdm_api:store_app", args=(sa_av.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "mdm.storeapp",
                 "pk": str(sa_av.store_app.pk),
                 "prev_value": prev_value,
             }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_store_app": [str(sa_av.store_app.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
        self.assertEqual(ArtifactVersion.objects.filter(pk=sa_av.pk).count(), 0)
        blueprint.refresh_from_db()
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 0)

from datetime import datetime
from functools import reduce
import json
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import APIToken, User
from zentral.contrib.inventory.models import MetaBusinessUnit, Tag
from zentral.contrib.monolith.models import (CacheServer, Catalog, Manifest, ManifestCatalog, ManifestSubManifest,
                                             SubManifest)


class MonolithAPIViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # service account
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True
        )
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        cls.api_key = APIToken.objects.update_or_create_for_user(user=cls.service_account)
        # mbu
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
        cls.mbu.create_enrollment_business_unit()
        # manifest
        cls.manifest = Manifest.objects.create(meta_business_unit=cls.mbu, name=get_random_string(12))

    # utility methods

    def _set_permissions(self, *permissions):
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

    def _post_data(self, url, data, content_type, include_token=True, ip=None):
        kwargs = {"content_type": content_type}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        if ip:
            kwargs["HTTP_X_REAL_IP"] = ip
        return self.client.post(url, data, **kwargs)

    def _put_data(self, url, data, content_type, include_token=True):
        kwargs = {"content_type": content_type}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.put(url, data, **kwargs)

    def _post_json_data(self, url, data, include_token=True, ip=None):
        content_type = "application/json"
        data = json.dumps(data)
        return self._post_data(url, data, content_type, include_token, ip)

    def _put_json_data(self, url, data, include_token=True):
        content_type = "application/json"
        data = json.dumps(data)
        return self._put_data(url, data, content_type, include_token)

    def get(self, url, data=None, include_token=True):
        kwargs = {}
        if data is not None:
            kwargs["data"] = data
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.get(url, **kwargs)

    def delete(self, url, include_token=True):
        kwargs = {}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.delete(url, **kwargs)

    def force_manifest(self, mbu=None, name=None):
        if mbu is None:
            mbu = self.mbu
        if name is None:
            name = get_random_string(12)
        return Manifest.objects.create(meta_business_unit=mbu, name=name)

    def force_catalog(self, name=None, archived=False):
        if name is None:
            name = get_random_string(12)
        archived_at = None
        if archived:
            archived_at = datetime.utcnow()
        return Catalog.objects.create(name=name, priority=1, archived_at=archived_at)

    def force_manifest_catalog(self, tag=None):
        manifest = self.force_manifest()
        catalog = self.force_catalog()
        mc = ManifestCatalog.objects.create(manifest=manifest, catalog=catalog)
        if tag:
            mc.tags.add(tag)
        return mc

    def force_manifest_sub_manifest(self, tag=None):
        manifest = self.force_manifest()
        sub_manifest = self.force_sub_manifest()
        msm = ManifestSubManifest.objects.create(manifest=manifest, sub_manifest=sub_manifest)
        if tag:
            msm.tags.add(tag)
        return msm

    def force_sub_manifest(self, meta_business_unit=None):
        return SubManifest.objects.create(
            name=get_random_string(12),
            description=get_random_string(12),
            meta_business_unit=meta_business_unit
        )

    # sync repository

    def test_sync_repository_unauthorized(self):
        response = self._post_json_data(reverse("monolith_api:sync_repository"), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_sync_repository_permission_denied(self):
        response = self._post_json_data(reverse("monolith_api:sync_repository"), {})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.contrib.monolith.api_views.monolith_conf.repository.sync_catalogs")
    def test_sync_repository(self, sync_catalogs):
        sync_catalogs.returns = True
        self._set_permissions(
            "monolith.view_catalog", "monolith.add_catalog", "monolith.change_catalog",
            "monolith.view_pkginfoname", "monolith.add_pkginfoname", "monolith.change_pkginfoname",
            "monolith.view_pkginfo", "monolith.add_pkginfo", "monolith.change_pkginfo",
            "monolith.change_manifest"
        )
        response = self._post_json_data(reverse("monolith_api:sync_repository"), {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {"status": 0})

    # update cache server

    def test_update_cache_server_unauthorized(self):
        response = self._post_json_data(reverse("monolith_api:update_cache_server", args=(self.manifest.pk,)),
                                        {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_cache_server_permission_denied(self):
        response = self._post_json_data(reverse("monolith_api:update_cache_server", args=(self.manifest.pk,)), {})
        self.assertEqual(response.status_code, 403)

    def test_update_cache_server(self):
        self._set_permissions("monolith.change_manifest", "monolith.add_cacheserver", "monolith.change_cacheserver")
        name = get_random_string(12)
        ip_address = "129.2.1.1"
        response = self._post_json_data(reverse("monolith_api:update_cache_server", args=(self.manifest.pk,)),
                                        {"name": name,
                                         "base_url": "https://example.com"},
                                        ip=ip_address)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": 0})
        cache_server = CacheServer.objects.get(manifest=self.manifest, name=name)
        self.assertEqual(cache_server.public_ip_address, ip_address)

    # list manifests

    def test_get_manifests_unauthorized(self):
        response = self.get(reverse("monolith_api:manifests"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_manifests_permission_denied(self):
        response = self.get(reverse("monolith_api:manifests"))
        self.assertEqual(response.status_code, 403)

    def test_get_manifests_filter_by_name_not_found(self):
        self._set_permissions("monolith.view_manifest")
        response = self.get(reverse("monolith_api:manifests"), {"name": "foo"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_get_manifests_filter_by_meta_business_unit_id_not_found(self):
        self._set_permissions("monolith.view_manifest")
        response = self.get(reverse("monolith_api:manifests"), {"meta_business_unit_id": 9999})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            'meta_business_unit_id': ['Select a valid choice. That choice is not one of the available choices.']
        })

    def test_get_manifests_filter_by_name(self):
        for _ in range(3):
            self.force_manifest()
        self._set_permissions("monolith.view_manifest")
        response = self.get(reverse("monolith_api:manifests"), {"name": self.manifest.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': self.manifest.pk,
            'name': self.manifest.name,
            'version': 1,
            'created_at': self.manifest.created_at.isoformat(),
            'updated_at': self.manifest.updated_at.isoformat(),
            'meta_business_unit': self.manifest.meta_business_unit.pk
        }])

    def test_get_manifests_filter_by_meta_business_unit_id(self):
        self._set_permissions("monolith.view_manifest")
        response = self.get(reverse("monolith_api:manifests"),
                            {"meta_business_unit_id": self.manifest.meta_business_unit.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': self.manifest.pk,
            'name': self.manifest.name,
            'version': 1,
            'created_at': self.manifest.created_at.isoformat(),
            'updated_at': self.manifest.updated_at.isoformat(),
            'meta_business_unit': self.manifest.meta_business_unit.pk
        }])

    def test_get_manifests(self):
        self._set_permissions("monolith.view_manifest")
        response = self.get(reverse("monolith_api:manifests"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': self.manifest.pk,
            'name': self.manifest.name,
            'version': 1,
            'created_at': self.manifest.created_at.isoformat(),
            'updated_at': self.manifest.updated_at.isoformat(),
            'meta_business_unit': self.manifest.meta_business_unit.pk
        }])

    # get manifest

    def test_get_manifest_unauthorized(self):
        response = self.get(reverse("monolith_api:manifest", args=(9999,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_manifest_permission_denied(self):
        response = self.get(reverse("monolith_api:manifest", args=(9999,)))
        self.assertEqual(response.status_code, 403)

    def test_get_manifest_not_found(self):
        self._set_permissions("monolith.view_manifest")
        response = self.get(reverse("monolith_api:manifest", args=(9999,)))
        self.assertEqual(response.status_code, 404)

    def test_get_manifest(self):
        self._set_permissions("monolith.view_manifest")
        response = self.get(reverse("monolith_api:manifest", args=(self.manifest.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            'id': self.manifest.pk,
            'name': self.manifest.name,
            'version': 1,
            'created_at': self.manifest.created_at.isoformat(),
            'updated_at': self.manifest.updated_at.isoformat(),
            'meta_business_unit': self.manifest.meta_business_unit.pk
        })

    # create manifest

    def test_create_manifest_unauthorized(self):
        response = self._post_json_data(reverse("monolith_api:manifests"), include_token=False, data={})
        self.assertEqual(response.status_code, 401)

    def test_create_manifest_permission_denied(self):
        response = self._post_json_data(reverse("monolith_api:manifests"), data={})
        self.assertEqual(response.status_code, 403)

    def test_create_manifest_fields_empty(self):
        self._set_permissions("monolith.add_manifest")
        response = self._post_json_data(reverse("monolith_api:manifests"), data={})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            'name': ['This field is required.'],
            'meta_business_unit': ['This field is required.']
        })

    def test_create_manifest(self):
        self._set_permissions("monolith.add_manifest")
        response = self._post_json_data(reverse("monolith_api:manifests"), data={
            'name': 'foo',
            'meta_business_unit': self.manifest.meta_business_unit.pk
        })
        self.assertEqual(response.status_code, 201)
        manifest = Manifest.objects.get(name='foo')
        self.assertEqual(response.json(), {
            'id': manifest.pk,
            'name': 'foo',
            'version': 1,
            'created_at': manifest.created_at.isoformat(),
            'updated_at': manifest.updated_at.isoformat(),
            'meta_business_unit': self.mbu.pk
        })
        self.assertEqual(manifest.name, 'foo')

    # update manifest

    def test_update_manifest_unauthorized(self):
        response = self._put_json_data(reverse("monolith_api:manifest", args=(9999,)), include_token=False, data={})
        self.assertEqual(response.status_code, 401)

    def test_update_manifest_permission_denied(self):
        response = self._put_json_data(reverse("monolith_api:manifest", args=(9999,)), data={})
        self.assertEqual(response.status_code, 403)

    def test_update_manifest_not_found(self):
        self._set_permissions("monolith.change_manifest")
        response = self._put_json_data(reverse("monolith_api:manifest", args=(9999,)), data={})
        self.assertEqual(response.status_code, 404)

    def test_update_manifest_fields_invalid(self):
        self._set_permissions("monolith.change_manifest")
        response = self._put_json_data(reverse("monolith_api:manifest", args=(self.manifest.pk,)), data={
            'name': '',
            'meta_business_unit': ''
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            'name': ['This field may not be blank.'],
            'meta_business_unit': ['This field may not be null.']
        })

    def test_update_manifest_invalid_meta_business_unit(self):
        manifest = self.force_manifest()
        self._set_permissions("monolith.change_manifest")
        response = self._put_json_data(reverse("monolith_api:manifest", args=(manifest.pk,)), data={
            'name': 'foo',
            'meta_business_unit': 9999
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            'meta_business_unit': ['Invalid pk "9999" - object does not exist.']
        })

    def test_update_manifest(self):
        manifest = self.force_manifest()
        self._set_permissions("monolith.change_manifest")
        response = self._put_json_data(reverse("monolith_api:manifest", args=(manifest.pk,)), data={
            'name': 'spam',
            'meta_business_unit': self.mbu.pk
        })
        self.assertEqual(response.status_code, 200)
        manifest.refresh_from_db()
        self.assertEqual(response.json(), {
            'id': manifest.pk,
            'name': 'spam',
            'version': 1,
            'created_at': manifest.created_at.isoformat(),
            'updated_at': manifest.updated_at.isoformat(),
            'meta_business_unit': self.mbu.pk
        })
        self.assertEqual(manifest.name, 'spam')

    # delete manifest

    def test_delete_manifest_unauthorized(self):
        response = self.delete(reverse("monolith_api:manifest", args=(9999,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_manifest_permission_denied(self):
        response = self.delete(reverse("monolith_api:manifest", args=(9999,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_manifest_not_found(self):
        self._set_permissions("monolith.delete_manifest")
        response = self.delete(reverse("monolith_api:manifest", args=(9999,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_manifest(self):
        manifest = self.force_manifest()
        self._set_permissions("monolith.delete_manifest")
        response = self.delete(reverse("monolith_api:manifest", args=(manifest.pk,)))
        self.assertEqual(response.status_code, 204)

    # list catalogs

    def test_get_catalogs_unauthorized(self):
        response = self.get(reverse("monolith_api:catalogs"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_catalogs_permission_denied(self):
        response = self.get(reverse("monolith_api:catalogs"))
        self.assertEqual(response.status_code, 403)

    def test_get_catalogs_filter_by_name_not_found(self):
        self._set_permissions("monolith.view_catalog")
        response = self.get(reverse("monolith_api:catalogs"), {"name": "foo"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_get_catalogs_filter_by_name(self):
        self.force_catalog()
        catalog = self.force_catalog()
        self._set_permissions("monolith.view_catalog")
        response = self.get(reverse("monolith_api:catalogs"), {"name": catalog.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': catalog.pk,
            'name': catalog.name,
            'priority': 1,
            'created_at': catalog.created_at.isoformat(),
            'updated_at': catalog.updated_at.isoformat(),
            'archived_at': None,
        }])

    def test_get_catalogs(self):
        catalog = self.force_catalog()
        self._set_permissions("monolith.view_catalog")
        response = self.get(reverse("monolith_api:catalogs"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': catalog.pk,
            'name': catalog.name,
            'priority': 1,
            'created_at': catalog.created_at.isoformat(),
            'updated_at': catalog.updated_at.isoformat(),
            'archived_at': None,
        }])

    # get catalog

    def test_get_catalog_unauthorized(self):
        response = self.get(reverse("monolith_api:catalog", args=(9999,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_catalog_permission_denied(self):
        response = self.get(reverse("monolith_api:catalog", args=(9999,)))
        self.assertEqual(response.status_code, 403)

    def test_get_catalog_not_found(self):
        self._set_permissions("monolith.view_catalog")
        response = self.get(reverse("monolith_api:catalog", args=(9999,)))
        self.assertEqual(response.status_code, 404)

    def test_get_catalog(self):
        catalog = self.force_catalog(archived=True)
        self._set_permissions("monolith.view_catalog")
        response = self.get(reverse("monolith_api:catalog", args=(catalog.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            'id': catalog.pk,
            'name': catalog.name,
            'priority': 1,
            'created_at': catalog.created_at.isoformat(),
            'updated_at': catalog.updated_at.isoformat(),
            'archived_at': catalog.archived_at.isoformat(),
        })

    # create catalog

    def test_create_catalog_unauthorized(self):
        response = self._post_json_data(reverse("monolith_api:catalogs"), include_token=False, data={})
        self.assertEqual(response.status_code, 401)

    def test_create_catalog_permission_denied(self):
        response = self._post_json_data(reverse("monolith_api:catalogs"), data={})
        self.assertEqual(response.status_code, 403)

    def test_create_catalog_fields_empty(self):
        self._set_permissions("monolith.add_catalog")
        response = self._post_json_data(reverse("monolith_api:catalogs"), data={})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            'name': ['This field is required.'],
        })

    def test_create_catalog(self):
        self._set_permissions("monolith.add_catalog")
        name = get_random_string(12)
        response = self._post_json_data(reverse("monolith_api:catalogs"), data={
            'name': name,
            'priority': 17,
            'archived_at': datetime.utcnow().isoformat(),
        })
        self.assertEqual(response.status_code, 201)
        catalog = Catalog.objects.get(name=name)
        self.assertEqual(response.json(), {
            'id': catalog.pk,
            'name': name,
            'priority': 17,
            'created_at': catalog.created_at.isoformat(),
            'updated_at': catalog.updated_at.isoformat(),
            'archived_at': None  # read only
        })
        self.assertEqual(catalog.priority, 17)

    # update catalog

    def test_update_catalog_unauthorized(self):
        response = self._put_json_data(reverse("monolith_api:catalog", args=(9999,)), include_token=False, data={})
        self.assertEqual(response.status_code, 401)

    def test_update_catalog_permission_denied(self):
        response = self._put_json_data(reverse("monolith_api:catalog", args=(9999,)), data={})
        self.assertEqual(response.status_code, 403)

    def test_update_catalog_not_found(self):
        self._set_permissions("monolith.change_catalog")
        response = self._put_json_data(reverse("monolith_api:catalog", args=(9999,)), data={})
        self.assertEqual(response.status_code, 404)

    def test_update_catalog_fields_invalid(self):
        catalog = self.force_catalog()
        self._set_permissions("monolith.change_catalog")
        response = self._put_json_data(reverse("monolith_api:catalog", args=(catalog.pk,)), data={
            'name': '',
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            'name': ['This field may not be blank.'],
        })

    def test_update_catalog(self):
        catalog = self.force_catalog()
        self._set_permissions("monolith.change_catalog")
        new_name = get_random_string(12)
        response = self._put_json_data(reverse("monolith_api:catalog", args=(catalog.pk,)), data={
            'name': new_name,
            'priority': 42,
        })
        self.assertEqual(response.status_code, 200)
        catalog.refresh_from_db()
        self.assertEqual(response.json(), {
            'id': catalog.pk,
            'name': new_name,
            'priority': 42,
            'created_at': catalog.created_at.isoformat(),
            'updated_at': catalog.updated_at.isoformat(),
            'archived_at': None
        })
        self.assertEqual(catalog.name, new_name)
        self.assertEqual(catalog.priority, 42)

    # delete catalog

    def test_delete_catalog_unauthorized(self):
        response = self.delete(reverse("monolith_api:catalog", args=(9999,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_catalog_permission_denied(self):
        response = self.delete(reverse("monolith_api:catalog", args=(9999,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_catalog_not_found(self):
        self._set_permissions("monolith.delete_catalog")
        response = self.delete(reverse("monolith_api:catalog", args=(9999,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_catalog_not_ok(self):
        catalog = self.force_catalog()
        self._set_permissions("monolith.delete_catalog")
        response = self.delete(reverse("monolith_api:catalog", args=(catalog.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ['This catalog cannot be deleted'])

    @patch("zentral.contrib.monolith.models.monolith_conf.repository")
    def test_delete_catalog(self, repository):
        repository.manual_catalog_management = True
        catalog = self.force_catalog()
        self._set_permissions("monolith.delete_catalog")
        response = self.delete(reverse("monolith_api:catalog", args=(catalog.pk,)))
        self.assertEqual(response.status_code, 204)

    # list manifest catalogs

    def test_get_manifest_catalogs_unauthorized(self):
        response = self.get(reverse("monolith_api:manifest_catalogs"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_manifest_catalogs_permission_denied(self):
        response = self.get(reverse("monolith_api:manifest_catalogs"))
        self.assertEqual(response.status_code, 403)

    def test_get_manifest_catalogs_filter_by_manifest_id_not_found(self):
        self._set_permissions("monolith.view_manifestcatalog")
        response = self.get(reverse("monolith_api:manifest_catalogs"), {"manifest_id": self.manifest.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_get_manifest_catalogs_filter_by_manifest_id(self):
        self.force_manifest_catalog()
        manifest_catalog = self.force_manifest_catalog()
        self._set_permissions("monolith.view_manifestcatalog")
        response = self.get(reverse("monolith_api:manifest_catalogs"),
                            {"manifest_id": manifest_catalog.manifest.id})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': manifest_catalog.pk,
            'manifest': manifest_catalog.manifest.id,
            'catalog': manifest_catalog.catalog.id,
            'tags': []
        }])

    def test_get_manifest_catalogs_filter_by_catalog_id(self):
        self.force_manifest_catalog()
        manifest_catalog = self.force_manifest_catalog()
        self._set_permissions("monolith.view_manifestcatalog")
        response = self.get(reverse("monolith_api:manifest_catalogs"),
                            {"catalog_id": manifest_catalog.catalog.id})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': manifest_catalog.pk,
            'manifest': manifest_catalog.manifest.id,
            'catalog': manifest_catalog.catalog.id,
            'tags': []
        }])

    def test_get_manifest_catalogs(self):
        manifest_catalog = self.force_manifest_catalog()
        self._set_permissions("monolith.view_manifestcatalog")
        response = self.get(reverse("monolith_api:manifest_catalogs"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': manifest_catalog.pk,
            'manifest': manifest_catalog.manifest.id,
            'catalog': manifest_catalog.catalog.id,
            'tags': []
        }])

    # get manifest catalog

    def test_get_manifest_catalog_unauthorized(self):
        response = self.get(reverse("monolith_api:manifest_catalog", args=(9999,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_manifest_catalog_permission_denied(self):
        response = self.get(reverse("monolith_api:manifest_catalog", args=(9999,)))
        self.assertEqual(response.status_code, 403)

    def test_get_manifest_catalog_not_found(self):
        self._set_permissions("monolith.view_manifestcatalog")
        response = self.get(reverse("monolith_api:manifest_catalog", args=(9999,)))
        self.assertEqual(response.status_code, 404)

    def test_get_manifest_catalog(self):
        tag = Tag.objects.create(name=get_random_string(12))
        manifest_catalog = self.force_manifest_catalog(tag=tag)
        self._set_permissions("monolith.view_manifestcatalog")
        response = self.get(reverse("monolith_api:manifest_catalog", args=(manifest_catalog.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            'id': manifest_catalog.pk,
            'manifest': manifest_catalog.manifest.id,
            'catalog': manifest_catalog.catalog.id,
            'tags': [tag.pk]
        })

    # create manifest catalog

    def test_create_manifest_catalog_unauthorized(self):
        response = self._post_json_data(reverse("monolith_api:manifest_catalogs"), include_token=False, data={})
        self.assertEqual(response.status_code, 401)

    def test_create_manifest_catalog_permission_denied(self):
        response = self._post_json_data(reverse("monolith_api:manifest_catalogs"), data={})
        self.assertEqual(response.status_code, 403)

    def test_create_manifest_catalog_fields_empty(self):
        self._set_permissions("monolith.add_manifestcatalog")
        response = self._post_json_data(reverse("monolith_api:manifest_catalogs"), data={})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            'manifest': ['This field is required.'],
            'catalog': ['This field is required.'],
            'tags': ['This field is required.'],
        })

    def test_create_manifest_catalog(self):
        self._set_permissions("monolith.add_manifestcatalog")
        manifest = self.force_manifest()
        catalog = self.force_catalog()
        tag = Tag.objects.create(name=get_random_string(12))
        response = self._post_json_data(reverse("monolith_api:manifest_catalogs"), data={
            'manifest': manifest.pk,
            'catalog': catalog.pk,
            'tags': [tag.pk],
        })
        self.assertEqual(response.status_code, 201)
        manifest_catalog = ManifestCatalog.objects.get(manifest=manifest, catalog=catalog)
        self.assertEqual(response.json(), {
            'id': manifest_catalog.pk,
            'manifest': manifest.pk,
            'catalog': catalog.pk,
            'tags': [tag.pk]
        })
        self.assertEqual(list(t.pk for t in manifest_catalog.tags.all()), [tag.pk])

    # update manifest catalog

    def test_update_manifest_catalog_unauthorized(self):
        response = self._put_json_data(reverse("monolith_api:manifest_catalog", args=(9999,)),
                                       include_token=False, data={})
        self.assertEqual(response.status_code, 401)

    def test_update_manifest_catalog_permission_denied(self):
        response = self._put_json_data(reverse("monolith_api:manifest_catalog", args=(9999,)), data={})
        self.assertEqual(response.status_code, 403)

    def test_update_manifest_catalog_not_found(self):
        self._set_permissions("monolith.change_manifestcatalog")
        response = self._put_json_data(reverse("monolith_api:manifest_catalog", args=(9999,)), data={})
        self.assertEqual(response.status_code, 404)

    def test_update_manifest_catalog(self):
        manifest_catalog = self.force_manifest_catalog()
        manifest = self.force_manifest()
        catalog = self.force_catalog()
        tag = Tag.objects.create(name=get_random_string(12))
        self._set_permissions("monolith.change_manifestcatalog")
        response = self._put_json_data(reverse("monolith_api:manifest_catalog", args=(manifest_catalog.pk,)), data={
            'manifest': manifest.pk,
            'catalog': catalog.pk,
            'tags': [tag.pk],
        })
        self.assertEqual(response.status_code, 200)
        test_manifest_catalog = ManifestCatalog.objects.get(manifest=manifest, catalog=catalog)
        self.assertEqual(manifest_catalog, test_manifest_catalog)
        self.assertEqual(response.json(), {
            'id': test_manifest_catalog.pk,
            'manifest': manifest.pk,
            'catalog': catalog.pk,
            'tags': [tag.pk]
        })
        self.assertEqual(list(t.pk for t in test_manifest_catalog.tags.all()), [tag.pk])

    # delete manifest catalog

    def test_delete_manifest_catalog_unauthorized(self):
        response = self.delete(reverse("monolith_api:manifest_catalog", args=(9999,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_manifest_catalog_permission_denied(self):
        response = self.delete(reverse("monolith_api:manifest_catalog", args=(9999,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_manifest_catalog_not_found(self):
        self._set_permissions("monolith.delete_manifestcatalog")
        response = self.delete(reverse("monolith_api:manifest_catalog", args=(9999,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_manifest_catalog(self):
        manifest_catalog = self.force_manifest_catalog()
        self._set_permissions("monolith.delete_manifestcatalog")
        response = self.delete(reverse("monolith_api:manifest_catalog", args=(manifest_catalog.pk,)))
        self.assertEqual(response.status_code, 204)

    # list manifest sub manifests

    def test_get_manifest_sub_manifests_unauthorized(self):
        response = self.get(reverse("monolith_api:manifest_sub_manifests"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_manifest_sub_manifests_permission_denied(self):
        response = self.get(reverse("monolith_api:manifest_sub_manifests"))
        self.assertEqual(response.status_code, 403)

    def test_get_manifest_sub_manifests_filter_by_manifest_id_not_found(self):
        self._set_permissions("monolith.view_manifestsubmanifest")
        response = self.get(reverse("monolith_api:manifest_sub_manifests"), {"manifest_id": self.manifest.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_get_manifest_sub_manifests_filter_by_manifest_id(self):
        self.force_manifest_sub_manifest()
        manifest_sub_manifest = self.force_manifest_sub_manifest()
        self._set_permissions("monolith.view_manifestsubmanifest")
        response = self.get(reverse("monolith_api:manifest_sub_manifests"),
                            {"manifest_id": manifest_sub_manifest.manifest.id})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': manifest_sub_manifest.pk,
            'manifest': manifest_sub_manifest.manifest.id,
            'sub_manifest': manifest_sub_manifest.sub_manifest.id,
            'tags': []
        }])

    def test_get_manifest_sub_manifests_filter_by_sub_manifest_id(self):
        self.force_manifest_sub_manifest()
        manifest_sub_manifest = self.force_manifest_sub_manifest()
        self._set_permissions("monolith.view_manifestsubmanifest")
        response = self.get(reverse("monolith_api:manifest_sub_manifests"),
                            {"sub_manifest_id": manifest_sub_manifest.sub_manifest.id})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': manifest_sub_manifest.pk,
            'manifest': manifest_sub_manifest.manifest.id,
            'sub_manifest': manifest_sub_manifest.sub_manifest.id,
            'tags': []
        }])

    def test_get_manifest_sub_manifests(self):
        manifest_sub_manifest = self.force_manifest_sub_manifest()
        self._set_permissions("monolith.view_manifestsubmanifest")
        response = self.get(reverse("monolith_api:manifest_sub_manifests"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': manifest_sub_manifest.pk,
            'manifest': manifest_sub_manifest.manifest.id,
            'sub_manifest': manifest_sub_manifest.sub_manifest.id,
            'tags': []
        }])

    # get manifest sub manifest

    def test_get_manifest_sub_manifest_unauthorized(self):
        response = self.get(reverse("monolith_api:manifest_sub_manifest", args=(9999,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_manifest_sub_manifest_permission_denied(self):
        response = self.get(reverse("monolith_api:manifest_sub_manifest", args=(9999,)))
        self.assertEqual(response.status_code, 403)

    def test_get_manifest_sub_manifest_not_found(self):
        self._set_permissions("monolith.view_manifestsubmanifest")
        response = self.get(reverse("monolith_api:manifest_sub_manifest", args=(9999,)))
        self.assertEqual(response.status_code, 404)

    def test_get_manifest_sub_manifest(self):
        tag = Tag.objects.create(name=get_random_string(12))
        manifest_sub_manifest = self.force_manifest_sub_manifest(tag=tag)
        self._set_permissions("monolith.view_manifestsubmanifest")
        response = self.get(reverse("monolith_api:manifest_sub_manifest", args=(manifest_sub_manifest.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            'id': manifest_sub_manifest.pk,
            'manifest': manifest_sub_manifest.manifest.id,
            'sub_manifest': manifest_sub_manifest.sub_manifest.id,
            'tags': [tag.pk]
        })

    # create manifest sub manifest

    def test_create_manifest_sub_manifest_unauthorized(self):
        response = self._post_json_data(reverse("monolith_api:manifest_sub_manifests"), include_token=False, data={})
        self.assertEqual(response.status_code, 401)

    def test_create_manifest_sub_manifest_permission_denied(self):
        response = self._post_json_data(reverse("monolith_api:manifest_sub_manifests"), data={})
        self.assertEqual(response.status_code, 403)

    def test_create_manifest_sub_manifest_fields_empty(self):
        self._set_permissions("monolith.add_manifestsubmanifest")
        response = self._post_json_data(reverse("monolith_api:manifest_sub_manifests"), data={})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            'manifest': ['This field is required.'],
            'sub_manifest': ['This field is required.'],
            'tags': ['This field is required.'],
        })

    def test_create_manifest_sub_manifest(self):
        self._set_permissions("monolith.add_manifestsubmanifest")
        manifest = self.force_manifest()
        sub_manifest = self.force_sub_manifest()
        tag = Tag.objects.create(name=get_random_string(12))
        response = self._post_json_data(reverse("monolith_api:manifest_sub_manifests"), data={
            'manifest': manifest.pk,
            'sub_manifest': sub_manifest.pk,
            'tags': [tag.pk],
        })
        self.assertEqual(response.status_code, 201)
        manifest_sub_manifest = ManifestSubManifest.objects.get(manifest=manifest, sub_manifest=sub_manifest)
        self.assertEqual(response.json(), {
            'id': manifest_sub_manifest.pk,
            'manifest': manifest.pk,
            'sub_manifest': sub_manifest.pk,
            'tags': [tag.pk]
        })
        self.assertEqual(list(t.pk for t in manifest_sub_manifest.tags.all()), [tag.pk])

    # update manifest sub manifest

    def test_update_manifest_sub_manifest_unauthorized(self):
        response = self._put_json_data(reverse("monolith_api:manifest_sub_manifest", args=(9999,)),
                                       include_token=False, data={})
        self.assertEqual(response.status_code, 401)

    def test_update_manifest_sub_manifest_permission_denied(self):
        response = self._put_json_data(reverse("monolith_api:manifest_sub_manifest", args=(9999,)), data={})
        self.assertEqual(response.status_code, 403)

    def test_update_manifest_sub_manifest_not_found(self):
        self._set_permissions("monolith.change_manifestsubmanifest")
        response = self._put_json_data(reverse("monolith_api:manifest_sub_manifest", args=(9999,)), data={})
        self.assertEqual(response.status_code, 404)

    def test_update_manifest_sub_manifest(self):
        manifest_sub_manifest = self.force_manifest_sub_manifest()
        manifest = self.force_manifest()
        sub_manifest = self.force_sub_manifest()
        tag = Tag.objects.create(name=get_random_string(12))
        self._set_permissions("monolith.change_manifestsubmanifest")
        response = self._put_json_data(
            reverse("monolith_api:manifest_sub_manifest", args=(manifest_sub_manifest.pk,)),
            data={
                'manifest': manifest.pk,
                'sub_manifest': sub_manifest.pk,
                'tags': [tag.pk],
            }
        )
        self.assertEqual(response.status_code, 200)
        test_manifest_sub_manifest = ManifestSubManifest.objects.get(manifest=manifest, sub_manifest=sub_manifest)
        self.assertEqual(manifest_sub_manifest, test_manifest_sub_manifest)
        self.assertEqual(response.json(), {
            'id': test_manifest_sub_manifest.pk,
            'manifest': manifest.pk,
            'sub_manifest': sub_manifest.pk,
            'tags': [tag.pk]
        })
        self.assertEqual(list(t.pk for t in test_manifest_sub_manifest.tags.all()), [tag.pk])

    # delete manifest sub manifest

    def test_delete_manifest_sub_manifest_unauthorized(self):
        response = self.delete(reverse("monolith_api:manifest_sub_manifest", args=(9999,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_manifest_sub_manifest_permission_denied(self):
        response = self.delete(reverse("monolith_api:manifest_sub_manifest", args=(9999,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_manifest_sub_manifest_not_found(self):
        self._set_permissions("monolith.delete_manifestsubmanifest")
        response = self.delete(reverse("monolith_api:manifest_sub_manifest", args=(9999,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_manifest_sub_manifest(self):
        manifest_sub_manifest = self.force_manifest_sub_manifest()
        self._set_permissions("monolith.delete_manifestsubmanifest")
        response = self.delete(reverse("monolith_api:manifest_sub_manifest", args=(manifest_sub_manifest.pk,)))
        self.assertEqual(response.status_code, 204)

    # list sub manifests

    def test_get_sub_manifests_unauthorized(self):
        response = self.get(reverse("monolith_api:sub_manifests"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_sub_manifests_permission_denied(self):
        response = self.get(reverse("monolith_api:sub_manifests"))
        self.assertEqual(response.status_code, 403)

    def test_get_sub_manifests_filter_by_name_not_found(self):
        self._set_permissions("monolith.view_submanifest")
        response = self.get(reverse("monolith_api:sub_manifests"), {"name": get_random_string(12)})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_get_sub_manifests_filter_by_name(self):
        self.force_sub_manifest()
        sub_manifest = self.force_sub_manifest()
        self._set_permissions("monolith.view_submanifest")
        response = self.get(reverse("monolith_api:sub_manifests"),
                            {"name": sub_manifest.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': sub_manifest.pk,
            'name': sub_manifest.name,
            'description': sub_manifest.description,
            'meta_business_unit': None,
            'created_at': sub_manifest.created_at.isoformat(),
            'updated_at': sub_manifest.updated_at.isoformat(),
        }])

    def test_get_sub_manifests(self):
        sub_manifest = self.force_sub_manifest(meta_business_unit=self.mbu)
        self._set_permissions("monolith.view_submanifest")
        response = self.get(reverse("monolith_api:sub_manifests"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': sub_manifest.pk,
            'name': sub_manifest.name,
            'description': sub_manifest.description,
            'meta_business_unit': self.mbu.pk,
            'created_at': sub_manifest.created_at.isoformat(),
            'updated_at': sub_manifest.updated_at.isoformat(),
        }])

    # get sub_manifest

    def test_get_sub_manifest_unauthorized(self):
        response = self.get(reverse("monolith_api:sub_manifest", args=(9999,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_sub_manifest_permission_denied(self):
        response = self.get(reverse("monolith_api:sub_manifest", args=(9999,)))
        self.assertEqual(response.status_code, 403)

    def test_get_sub_manifest_not_found(self):
        self._set_permissions("monolith.view_submanifest")
        response = self.get(reverse("monolith_api:sub_manifest", args=(9999,)))
        self.assertEqual(response.status_code, 404)

    def test_get_sub_manifest(self):
        sub_manifest = self.force_sub_manifest()
        self._set_permissions("monolith.view_submanifest")
        response = self.get(reverse("monolith_api:sub_manifest", args=(sub_manifest.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            'id': sub_manifest.pk,
            'name': sub_manifest.name,
            'description': sub_manifest.description,
            'meta_business_unit': None,
            'created_at': sub_manifest.created_at.isoformat(),
            'updated_at': sub_manifest.updated_at.isoformat(),
        })

    # create sub_manifest

    def test_create_sub_manifest_unauthorized(self):
        response = self._post_json_data(reverse("monolith_api:sub_manifests"), include_token=False, data={})
        self.assertEqual(response.status_code, 401)

    def test_create_sub_manifest_permission_denied(self):
        response = self._post_json_data(reverse("monolith_api:sub_manifests"), data={})
        self.assertEqual(response.status_code, 403)

    def test_create_sub_manifest_fields_empty(self):
        self._set_permissions("monolith.add_submanifest")
        response = self._post_json_data(reverse("monolith_api:sub_manifests"), data={})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            'name': ['This field is required.'],
        })

    def test_create_sub_manifest(self):
        self._set_permissions("monolith.add_submanifest")
        name = get_random_string(12)
        response = self._post_json_data(reverse("monolith_api:sub_manifests"), data={
            'name': name,
        })
        self.assertEqual(response.status_code, 201)
        sub_manifest = SubManifest.objects.get(name=name)
        self.assertEqual(response.json(), {
            'id': sub_manifest.pk,
            'name': name,
            'description': "",
            'meta_business_unit': None,
            'created_at': sub_manifest.created_at.isoformat(),
            'updated_at': sub_manifest.updated_at.isoformat(),
        })
        self.assertEqual(sub_manifest.description, "")
        self.assertIsNone(sub_manifest.meta_business_unit)

    # update sub_manifest

    def test_update_sub_manifest_unauthorized(self):
        response = self._put_json_data(reverse("monolith_api:sub_manifest", args=(9999,)),
                                       include_token=False, data={})
        self.assertEqual(response.status_code, 401)

    def test_update_sub_manifest_permission_denied(self):
        response = self._put_json_data(reverse("monolith_api:sub_manifest", args=(9999,)), data={})
        self.assertEqual(response.status_code, 403)

    def test_update_sub_manifest_not_found(self):
        self._set_permissions("monolith.change_submanifest")
        response = self._put_json_data(reverse("monolith_api:sub_manifest", args=(9999,)), data={})
        self.assertEqual(response.status_code, 404)

    def test_update_sub_manifest(self):
        sub_manifest = self.force_sub_manifest()
        self._set_permissions("monolith.change_submanifest")
        new_name = get_random_string(12)
        new_description = get_random_string(12)
        response = self._put_json_data(reverse("monolith_api:sub_manifest", args=(sub_manifest.pk,)), data={
            'name': new_name,
            'description': new_description,
            'meta_business_unit': self.mbu.pk,
        })
        self.assertEqual(response.status_code, 200)
        test_sub_manifest = SubManifest.objects.get(name=new_name)
        self.assertEqual(sub_manifest, test_sub_manifest)
        self.assertEqual(response.json(), {
            'id': test_sub_manifest.pk,
            'name': new_name,
            'description': new_description,
            'meta_business_unit': self.mbu.pk,
            'created_at': test_sub_manifest.created_at.isoformat(),
            'updated_at': test_sub_manifest.updated_at.isoformat(),
        })
        self.assertEqual(test_sub_manifest.description, new_description)
        self.assertEqual(test_sub_manifest.meta_business_unit, self.mbu)

    # delete sub_manifest

    def test_delete_sub_manifest_unauthorized(self):
        response = self.delete(reverse("monolith_api:sub_manifest", args=(9999,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_sub_manifest_permission_denied(self):
        response = self.delete(reverse("monolith_api:sub_manifest", args=(9999,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_sub_manifest_not_found(self):
        self._set_permissions("monolith.delete_submanifest")
        response = self.delete(reverse("monolith_api:sub_manifest", args=(9999,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_sub_manifest(self):
        sub_manifest = self.force_sub_manifest()
        self._set_permissions("monolith.delete_submanifest")
        response = self.delete(reverse("monolith_api:sub_manifest", args=(sub_manifest.pk,)))
        self.assertEqual(response.status_code, 204)

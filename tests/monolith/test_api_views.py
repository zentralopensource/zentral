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
from zentral.conf import settings
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit, Tag
from zentral.contrib.inventory.serializers import EnrollmentSecretSerializer
from zentral.contrib.monolith.models import (CacheServer, Catalog, Condition, Enrollment,
                                             Manifest, ManifestCatalog, ManifestSubManifest,
                                             PkgInfoName,
                                             SubManifest, SubManifestAttachment, SubManifestPkgInfo)


class MonolithAPIViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        # service account
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True
        )
        cls.user = User.objects.create_user(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            password=get_random_string(12)
        )
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        cls.user.groups.set([cls.group])
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

    def force_catalog(self, name=None, archived=False):
        if name is None:
            name = get_random_string(12)
        archived_at = None
        if archived:
            archived_at = datetime.utcnow()
        return Catalog.objects.create(name=name, priority=1, archived_at=archived_at)

    def force_condition(self):
        return Condition.objects.create(
            name=get_random_string(),
            predicate=get_random_string()
        )

    def force_enrollment(self, tag_count=0):
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=self.mbu)
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(tag_count)]
        if tags:
            enrollment_secret.tags.set(tags)
        return (
            Enrollment.objects.create(manifest=self.force_manifest(), secret=enrollment_secret),
            tags
        )

    def force_manifest(self, mbu=None, name=None):
        if mbu is None:
            mbu = self.mbu
        if name is None:
            name = get_random_string(12)
        return Manifest.objects.create(meta_business_unit=mbu, name=name)

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

    def force_pkg_info_name(self):
        return PkgInfoName.objects.create(name=get_random_string(12))

    def force_sub_manifest(self, meta_business_unit=None):
        return SubManifest.objects.create(
            name=get_random_string(12),
            description=get_random_string(12),
            meta_business_unit=meta_business_unit
        )

    def force_sub_manifest_attachment(self, sub_manifest=None, condition=None):
        if sub_manifest is None:
            sub_manifest = self.force_sub_manifest()
        return SubManifestAttachment.objects.create(
            sub_manifest=sub_manifest,
            key="managed_installs",
            type="script",
            name=get_random_string(12),
            condition=condition,
            pkg_info={}
        )

    def force_sub_manifest_pkg_info(self, sub_manifest=None, options=None):
        if sub_manifest is None:
            sub_manifest = self.force_sub_manifest()
        if options is None:
            options = {}
        return SubManifestPkgInfo.objects.create(
            sub_manifest=sub_manifest,
            key="managed_installs",
            pkg_info_name=self.force_pkg_info_name(),
            options=options
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
        manifest_catalog = self.force_manifest_catalog()
        self._set_permissions("monolith.delete_catalog")
        response = self.delete(reverse("monolith_api:catalog", args=(manifest_catalog.catalog.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ['This catalog cannot be deleted'])

    def test_delete_catalog(self):
        catalog = self.force_catalog()
        self._set_permissions("monolith.delete_catalog")
        response = self.delete(reverse("monolith_api:catalog", args=(catalog.pk,)))
        self.assertEqual(response.status_code, 204)

    # list conditions

    def test_get_conditions_unauthorized(self):
        response = self.get(reverse("monolith_api:conditions"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_conditions_permission_denied(self):
        response = self.get(reverse("monolith_api:conditions"))
        self.assertEqual(response.status_code, 403)

    def test_get_conditions_filter_by_name_not_found(self):
        self._set_permissions("monolith.view_condition")
        response = self.get(reverse("monolith_api:conditions"), {"name": "foo"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_get_conditions_filter_by_name(self):
        self.force_condition()
        condition = self.force_condition()
        self._set_permissions("monolith.view_condition")
        response = self.get(reverse("monolith_api:conditions"), {"name": condition.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': condition.pk,
            'name': condition.name,
            'predicate': condition.predicate,
            'created_at': condition.created_at.isoformat(),
            'updated_at': condition.updated_at.isoformat(),
        }])

    def test_get_conditions(self):
        condition = self.force_condition()
        self._set_permissions("monolith.view_condition")
        response = self.get(reverse("monolith_api:conditions"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': condition.pk,
            'name': condition.name,
            'predicate': condition.predicate,
            'created_at': condition.created_at.isoformat(),
            'updated_at': condition.updated_at.isoformat(),
        }])

    # get condition

    def test_get_condition_unauthorized(self):
        response = self.get(reverse("monolith_api:condition", args=(9999,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_condition_permission_denied(self):
        response = self.get(reverse("monolith_api:condition", args=(9999,)))
        self.assertEqual(response.status_code, 403)

    def test_get_condition_not_found(self):
        self._set_permissions("monolith.view_condition")
        response = self.get(reverse("monolith_api:condition", args=(9999,)))
        self.assertEqual(response.status_code, 404)

    def test_get_condition(self):
        condition = self.force_condition()
        self._set_permissions("monolith.view_condition")
        response = self.get(reverse("monolith_api:condition", args=(condition.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            'id': condition.pk,
            'name': condition.name,
            'predicate': condition.predicate,
            'created_at': condition.created_at.isoformat(),
            'updated_at': condition.updated_at.isoformat(),
        })

    # create condition

    def test_create_condition_unauthorized(self):
        response = self._post_json_data(reverse("monolith_api:conditions"), include_token=False, data={})
        self.assertEqual(response.status_code, 401)

    def test_create_condition_permission_denied(self):
        response = self._post_json_data(reverse("monolith_api:conditions"), data={})
        self.assertEqual(response.status_code, 403)

    def test_create_condition_fields_empty(self):
        self._set_permissions("monolith.add_condition")
        response = self._post_json_data(reverse("monolith_api:conditions"), data={})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            'name': ['This field is required.'],
            'predicate': ['This field is required.'],
        })

    def test_create_condition(self):
        self._set_permissions("monolith.add_condition")
        name = get_random_string(12)
        predicate = get_random_string(12)
        response = self._post_json_data(reverse("monolith_api:conditions"), data={
            'name': name,
            'predicate': predicate,
        })
        self.assertEqual(response.status_code, 201)
        condition = Condition.objects.get(name=name)
        self.assertEqual(response.json(), {
            'id': condition.pk,
            'name': name,
            'predicate': predicate,
            'created_at': condition.created_at.isoformat(),
            'updated_at': condition.updated_at.isoformat(),
        })
        self.assertEqual(condition.predicate, predicate)

    def test_create_condition_name_conflict(self):
        condition = self.force_condition()
        self._set_permissions("monolith.add_condition")
        response = self._post_json_data(reverse("monolith_api:conditions"), data={
            'name': condition.name,
            'predicate': get_random_string(12)
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'name': ['condition with this name already exists.']})

    # update condition

    def test_update_condition_unauthorized(self):
        response = self._put_json_data(reverse("monolith_api:condition", args=(9999,)), include_token=False, data={})
        self.assertEqual(response.status_code, 401)

    def test_update_condition_permission_denied(self):
        response = self._put_json_data(reverse("monolith_api:condition", args=(9999,)), data={})
        self.assertEqual(response.status_code, 403)

    def test_update_condition_not_found(self):
        self._set_permissions("monolith.change_condition")
        response = self._put_json_data(reverse("monolith_api:condition", args=(9999,)), data={})
        self.assertEqual(response.status_code, 404)

    def test_update_condition_fields_invalid(self):
        condition = self.force_condition()
        self._set_permissions("monolith.change_condition")
        response = self._put_json_data(reverse("monolith_api:condition", args=(condition.pk,)), data={
            'name': '',
            'predicate': '',
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            'name': ['This field may not be blank.'],
            'predicate': ['This field may not be blank.'],
        })

    def test_update_condition(self):
        condition = self.force_condition()
        self._set_permissions("monolith.change_condition")
        new_name = get_random_string(12)
        new_predicate = get_random_string(12)
        response = self._put_json_data(reverse("monolith_api:condition", args=(condition.pk,)), data={
            'name': new_name,
            'predicate': new_predicate,
        })
        self.assertEqual(response.status_code, 200)
        condition.refresh_from_db()
        self.assertEqual(response.json(), {
            'id': condition.pk,
            'name': new_name,
            'predicate': new_predicate,
            'created_at': condition.created_at.isoformat(),
            'updated_at': condition.updated_at.isoformat(),
        })
        self.assertEqual(condition.name, new_name)
        self.assertEqual(condition.predicate, new_predicate)

    def test_update_condition_name_conflict(self):
        condition1 = self.force_condition()
        condition2 = self.force_condition()
        self._set_permissions("monolith.change_condition")
        response = self._put_json_data(reverse("monolith_api:condition", args=(condition2.pk,)), data={
            'name': condition1.name,
            'predicate': condition2.predicate,
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'name': ['condition with this name already exists.']})

    # delete condition

    def test_delete_condition_unauthorized(self):
        response = self.delete(reverse("monolith_api:condition", args=(9999,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_condition_permission_denied(self):
        response = self.delete(reverse("monolith_api:condition", args=(9999,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_condition_not_found(self):
        self._set_permissions("monolith.delete_condition")
        response = self.delete(reverse("monolith_api:condition", args=(9999,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_condition_not_ok(self):
        condition = self.force_condition()
        self.force_sub_manifest_attachment(condition=condition)
        self._set_permissions("monolith.delete_condition")
        response = self.delete(reverse("monolith_api:condition", args=(condition.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ['This condition cannot be deleted'])

    def test_delete_condition(self):
        condition = self.force_condition()
        self._set_permissions("monolith.delete_condition")
        response = self.delete(reverse("monolith_api:condition", args=(condition.pk,)))
        self.assertEqual(response.status_code, 204)

    # list enrollments

    def test_get_enrollments_unauthorized(self):
        response = self.get(reverse("monolith_api:enrollments"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollments_permission_denied(self):
        response = self.get(reverse("monolith_api:enrollments"))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollments_filter_by_manifest_id_invalid_choice(self):
        self._set_permissions("monolith.view_enrollment")
        response = self.get(reverse("monolith_api:enrollments"), {"manifest_id": 9999})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'manifest_id': ['Select a valid choice. That choice is not one of the available choices.']}
        )

    def test_get_enrollments_filter_by_manifest_id_no_results(self):
        self._set_permissions("monolith.view_enrollment")
        manifest = self.force_manifest()
        response = self.get(reverse("monolith_api:enrollments"), {"manifest_id": manifest.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_get_enrollments_filter_by_manifest_id(self):
        enrollment, tags = self.force_enrollment(tag_count=1)
        self._set_permissions("monolith.view_enrollment")
        response = self.get(reverse("monolith_api:enrollments"), {"manifest_id": enrollment.manifest.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': enrollment.pk,
            'manifest': enrollment.manifest.pk,
            'enrolled_machines_count': 0,
            'secret': {
                'id': enrollment.secret.pk,
                'secret': enrollment.secret.secret,
                'meta_business_unit': self.mbu.pk,
                'tags': [t.pk for t in tags],
                'serial_numbers': None,
                'udids': None,
                'quota': None,
                'request_count': 0
            },
            'version': 1,
            'configuration_profile_download_url': (
                 f'https://{settings["api"]["fqdn"]}'
                 f'{reverse("monolith_api:enrollment_configuration_profile", args=(enrollment.pk,))}'
            ),
            'plist_download_url': (
                 f'https://{settings["api"]["fqdn"]}'
                 f'{reverse("monolith_api:enrollment_plist", args=(enrollment.pk,))}'
            ),
            'created_at': enrollment.created_at.isoformat(),
            'updated_at': enrollment.updated_at.isoformat(),
        }])

    def test_get_enrollments(self):
        enrollment, _ = self.force_enrollment()
        self._set_permissions("monolith.view_enrollment")
        response = self.get(reverse("monolith_api:enrollments"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': enrollment.pk,
            'manifest': enrollment.manifest.pk,
            'enrolled_machines_count': 0,
            'secret': {
                'id': enrollment.secret.pk,
                'secret': enrollment.secret.secret,
                'meta_business_unit': self.mbu.pk,
                'tags': [],
                'serial_numbers': None,
                'udids': None,
                'quota': None,
                'request_count': 0
            },
            'version': 1,
            'configuration_profile_download_url': (
                 f'https://{settings["api"]["fqdn"]}'
                 f'{reverse("monolith_api:enrollment_configuration_profile", args=(enrollment.pk,))}'
            ),
            'plist_download_url': (
                 f'https://{settings["api"]["fqdn"]}'
                 f'{reverse("monolith_api:enrollment_plist", args=(enrollment.pk,))}'
            ),
            'created_at': enrollment.created_at.isoformat(),
            'updated_at': enrollment.updated_at.isoformat(),
        }])

    # get enrollment

    def test_get_enrollment_unauthorized(self):
        response = self.get(reverse("monolith_api:enrollment", args=(9999,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollment_permission_denied(self):
        response = self.get(reverse("monolith_api:enrollment", args=(9999,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_not_found(self):
        self._set_permissions("monolith.view_enrollment")
        response = self.get(reverse("monolith_api:enrollment", args=(9999,)))
        self.assertEqual(response.status_code, 404)

    def test_get_enrollment(self):
        enrollment, _ = self.force_enrollment()
        self._set_permissions("monolith.view_enrollment")
        response = self.get(reverse("monolith_api:enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            'id': enrollment.pk,
            'manifest': enrollment.manifest.pk,
            'enrolled_machines_count': 0,
            'secret': {
                'id': enrollment.secret.pk,
                'secret': enrollment.secret.secret,
                'meta_business_unit': self.mbu.pk,
                'tags': [],
                'serial_numbers': None,
                'udids': None,
                'quota': None,
                'request_count': 0
            },
            'version': 1,
            'configuration_profile_download_url': (
                 f'https://{settings["api"]["fqdn"]}'
                 f'{reverse("monolith_api:enrollment_configuration_profile", args=(enrollment.pk,))}'
            ),
            'plist_download_url': (
                 f'https://{settings["api"]["fqdn"]}'
                 f'{reverse("monolith_api:enrollment_plist", args=(enrollment.pk,))}'
            ),
            'created_at': enrollment.created_at.isoformat(),
            'updated_at': enrollment.updated_at.isoformat(),
        })

    # create enrollment

    def test_create_enrollment_unauthorized(self):
        response = self._post_json_data(reverse("monolith_api:enrollments"), include_token=False, data={})
        self.assertEqual(response.status_code, 401)

    def test_create_enrollment_permission_denied(self):
        response = self._post_json_data(reverse("monolith_api:enrollments"), data={})
        self.assertEqual(response.status_code, 403)

    def test_create_enrollment_fields_empty(self):
        self._set_permissions("monolith.add_enrollment")
        response = self._post_json_data(reverse("monolith_api:enrollments"), data={})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            'manifest': ['This field is required.'],
            'secret': ['This field is required.'],
        })

    def test_create_enrollment(self):
        self._set_permissions("monolith.add_enrollment")
        manifest = self.force_manifest()
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(1)]
        response = self._post_json_data(reverse("monolith_api:enrollments"), data={
            'manifest': manifest.pk,
            'secret': {
                'meta_business_unit': self.mbu.pk,
                'tags': [t.id for t in tags]
            }
        })
        self.assertEqual(response.status_code, 201)
        enrollment = Enrollment.objects.get(manifest=manifest)
        self.assertEqual(response.json(), {
            'id': enrollment.pk,
            'manifest': enrollment.manifest.pk,
            'enrolled_machines_count': 0,
            'secret': {
                'id': enrollment.secret.pk,
                'secret': enrollment.secret.secret,
                'meta_business_unit': self.mbu.pk,
                'tags': [t.id for t in tags],
                'serial_numbers': None,
                'udids': None,
                'quota': None,
                'request_count': 0
            },
            'version': 1,
            'configuration_profile_download_url': (
                 f'https://{settings["api"]["fqdn"]}'
                 f'{reverse("monolith_api:enrollment_configuration_profile", args=(enrollment.pk,))}'
            ),
            'plist_download_url': (
                 f'https://{settings["api"]["fqdn"]}'
                 f'{reverse("monolith_api:enrollment_plist", args=(enrollment.pk,))}'
            ),
            'created_at': enrollment.created_at.isoformat(),
            'updated_at': enrollment.updated_at.isoformat(),
        })

    # update enrollment

    def test_update_enrollment_unauthorized(self):
        response = self._put_json_data(reverse("monolith_api:enrollment", args=(9999,)), include_token=False, data={})
        self.assertEqual(response.status_code, 401)

    def test_update_enrollment_permission_denied(self):
        response = self._put_json_data(reverse("monolith_api:enrollment", args=(9999,)), data={})
        self.assertEqual(response.status_code, 403)

    def test_update_enrollment_not_found(self):
        self._set_permissions("monolith.change_enrollment")
        response = self._put_json_data(reverse("monolith_api:enrollment", args=(9999,)), data={})
        self.assertEqual(response.status_code, 404)

    def test_update_enrollment(self):
        enrollment, _ = self.force_enrollment(tag_count=2)
        enrollment_secret = enrollment.secret
        self.assertEqual(enrollment.secret.quota, None)
        self.assertEqual(enrollment.secret.serial_numbers, None)
        self.assertEqual(enrollment.secret.tags.count(), 2)
        secret_data = EnrollmentSecretSerializer(enrollment_secret).data
        secret_data["id"] = 233333  # to check that there is no enrollment secret creation
        secret_data["quota"] = 23
        secret_data["request_count"] = 2331983  # to check that it cannot be updated
        serial_numbers = [get_random_string(12) for i in range(13)]
        secret_data["serial_numbers"] = serial_numbers
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(2)]
        secret_data["tags"] = [t.id for t in tags]
        self._set_permissions("monolith.change_enrollment")
        response = self._put_json_data(reverse("monolith_api:enrollment", args=(enrollment.pk,)), data={
            'manifest': enrollment.manifest.pk,
            'secret': secret_data
        })
        self.assertEqual(response.status_code, 200)
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.secret, enrollment_secret)
        self.assertEqual(enrollment.secret.quota, 23)
        self.assertEqual(enrollment.secret.request_count, 0)
        self.assertEqual(enrollment.secret.serial_numbers, serial_numbers)
        self.assertEqual(
            set(enrollment.secret.tags.all()),
            set(tags)
        )

    # delete enrollment

    def test_delete_enrollment_unauthorized(self):
        response = self.delete(reverse("monolith_api:enrollment", args=(9999,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_enrollment_permission_denied(self):
        response = self.delete(reverse("monolith_api:enrollment", args=(9999,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_enrollment_not_found(self):
        self._set_permissions("monolith.delete_enrollment")
        response = self.delete(reverse("monolith_api:enrollment", args=(9999,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_enrollment(self):
        enrollment, _ = self.force_enrollment()
        self._set_permissions("monolith.delete_enrollment")
        response = self.delete(reverse("monolith_api:enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 204)

    # enrollment plist

    def test_get_enrollment_plist_unauthorized(self):
        enrollment, _ = self.force_enrollment()
        response = self.get(reverse("monolith_api:enrollment_plist", args=(enrollment.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollment_plist_permission_denied(self):
        enrollment, _ = self.force_enrollment()
        response = self.get(reverse("monolith_api:enrollment_plist", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_plist_permission_denied_user(self):
        enrollment, _ = self.force_enrollment()
        self.client.force_login(self.user)
        response = self.client.get(reverse("monolith_api:enrollment_plist", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_plist(self):
        enrollment, _ = self.force_enrollment()
        self._set_permissions("monolith.view_enrollment")
        response = self.get(reverse("monolith_api:enrollment_plist", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/x-plist')
        self.assertEqual(response['Content-Disposition'],
                         f'attachment; filename="zentral_monolith_configuration.enrollment_{enrollment.pk}.plist"')
        self.assertEqual(int(response['Content-Length']), len(response.content))

    def test_get_enrollment_plist_user(self):
        enrollment, _ = self.force_enrollment()
        self._set_permissions("monolith.view_enrollment")
        self.client.force_login(self.user)
        response = self.client.get(reverse("monolith_api:enrollment_plist", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/x-plist')
        self.assertEqual(response['Content-Disposition'],
                         f'attachment; filename="zentral_monolith_configuration.enrollment_{enrollment.pk}.plist"')
        self.assertEqual(int(response['Content-Length']), len(response.content))

    # enrollment configuration profile

    def test_get_enrollment_configuration_profile_unauthorized(self):
        enrollment, _ = self.force_enrollment()
        response = self.get(
            reverse("monolith_api:enrollment_configuration_profile", args=(enrollment.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollment_configuration_profile_permission_denied(self):
        enrollment, _ = self.force_enrollment()
        response = self.get(reverse("monolith_api:enrollment_configuration_profile", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_configuration_profile_permission_denied_user(self):
        enrollment, _ = self.force_enrollment()
        self.client.force_login(self.user)
        response = self.client.get(reverse("monolith_api:enrollment_configuration_profile", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_configuration_profile(self):
        enrollment, _ = self.force_enrollment()
        self._set_permissions("monolith.view_enrollment")
        response = self.get(reverse("monolith_api:enrollment_configuration_profile", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/octet-stream')
        self.assertEqual(
            response['Content-Disposition'],
            f'attachment; filename="zentral_monolith_configuration.enrollment_{enrollment.pk}.mobileconfig"'
        )
        self.assertEqual(int(response['Content-Length']), len(response.content))

    def test_get_enrollment_configuration_profile_user(self):
        enrollment, _ = self.force_enrollment()
        self._set_permissions("monolith.view_enrollment")
        self.client.force_login(self.user)
        response = self.client.get(reverse("monolith_api:enrollment_configuration_profile", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/octet-stream')
        self.assertEqual(
            response['Content-Disposition'],
            f'attachment; filename="zentral_monolith_configuration.enrollment_{enrollment.pk}.mobileconfig"'
        )
        self.assertEqual(int(response['Content-Length']), len(response.content))

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
        manifest_catalog = self.force_manifest_catalog(
            tag=Tag.objects.create(name=get_random_string(12))
        )
        self.assertEqual(manifest_catalog.tags.count(), 1)
        manifest = self.force_manifest()
        catalog = self.force_catalog()
        self._set_permissions("monolith.change_manifestcatalog")
        response = self._put_json_data(reverse("monolith_api:manifest_catalog", args=(manifest_catalog.pk,)), data={
            'manifest': manifest.pk,
            'catalog': catalog.pk,
            'tags': [],
        })
        self.assertEqual(response.status_code, 200)
        test_manifest_catalog = ManifestCatalog.objects.get(manifest=manifest, catalog=catalog)
        self.assertEqual(manifest_catalog, test_manifest_catalog)
        self.assertEqual(response.json(), {
            'id': test_manifest_catalog.pk,
            'manifest': manifest.pk,
            'catalog': catalog.pk,
            'tags': []
        })
        self.assertEqual(test_manifest_catalog.tags.count(), 0)

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
        manifest_sub_manifest = self.force_manifest_sub_manifest(
            tag=Tag.objects.create(name=get_random_string(12))
        )
        self.assertEqual(manifest_sub_manifest.tags.count(), 1)
        manifest = self.force_manifest()
        sub_manifest = self.force_sub_manifest()
        self._set_permissions("monolith.change_manifestsubmanifest")
        response = self._put_json_data(
            reverse("monolith_api:manifest_sub_manifest", args=(manifest_sub_manifest.pk,)),
            data={
                'manifest': manifest.pk,
                'sub_manifest': sub_manifest.pk,
                'tags': [],
            }
        )
        self.assertEqual(response.status_code, 200)
        test_manifest_sub_manifest = ManifestSubManifest.objects.get(manifest=manifest, sub_manifest=sub_manifest)
        self.assertEqual(manifest_sub_manifest, test_manifest_sub_manifest)
        self.assertEqual(response.json(), {
            'id': test_manifest_sub_manifest.pk,
            'manifest': manifest.pk,
            'sub_manifest': sub_manifest.pk,
            'tags': []
        })
        self.assertEqual(test_manifest_sub_manifest.tags.count(), 0)

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

    # get sub manifest

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

    # create sub manifest

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

    # update sub manifest

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

    # delete sub manifest

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

    # list sub manifest pkg infos

    def test_get_sub_manifest_pkg_infos_unauthorized(self):
        response = self.get(reverse("monolith_api:sub_manifest_pkg_infos"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_sub_manifest_pkg_infos_permission_denied(self):
        response = self.get(reverse("monolith_api:sub_manifest_pkg_infos"))
        self.assertEqual(response.status_code, 403)

    def test_get_sub_manifest_pkg_infos_filter_by_sub_manifest_id_not_found(self):
        self._set_permissions("monolith.view_submanifestpkginfo")
        sub_manifest = self.force_sub_manifest()
        response = self.get(reverse("monolith_api:sub_manifest_pkg_infos"), {"sub_manifest_id": sub_manifest.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_get_sub_manifest_pkg_infos_filter_by_sub_manifest_id(self):
        self.force_sub_manifest_pkg_info()
        sub_manifest_pkg_info = self.force_sub_manifest_pkg_info()
        self._set_permissions("monolith.view_submanifestpkginfo")
        response = self.get(reverse("monolith_api:sub_manifest_pkg_infos"),
                            {"sub_manifest_id": sub_manifest_pkg_info.sub_manifest.id})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': sub_manifest_pkg_info.pk,
            'sub_manifest': sub_manifest_pkg_info.sub_manifest.pk,
            'key': 'managed_installs',
            'pkg_info_name': sub_manifest_pkg_info.pkg_info_name.name,
            'featured_item': False,
            'condition': None,
            'shard_modulo': 100,
            'default_shard': 100,
            'excluded_tags': [],
            'tag_shards': [],
            'created_at': sub_manifest_pkg_info.created_at.isoformat(),
            'updated_at': sub_manifest_pkg_info.updated_at.isoformat(),
        }])

    def test_get_sub_manifest_pkg_infos(self):
        sub_manifest_pkg_info = self.force_sub_manifest_pkg_info()
        self._set_permissions("monolith.view_submanifestpkginfo")
        response = self.get(reverse("monolith_api:sub_manifest_pkg_infos"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': sub_manifest_pkg_info.pk,
            'sub_manifest': sub_manifest_pkg_info.sub_manifest.pk,
            'key': 'managed_installs',
            'pkg_info_name': sub_manifest_pkg_info.pkg_info_name.name,
            'featured_item': False,
            'condition': None,
            'shard_modulo': 100,
            'default_shard': 100,
            'excluded_tags': [],
            'tag_shards': [],
            'created_at': sub_manifest_pkg_info.created_at.isoformat(),
            'updated_at': sub_manifest_pkg_info.updated_at.isoformat(),
        }])

    # get sub manifest pkg info

    def test_get_sub_manifest_pkg_info_unauthorized(self):
        response = self.get(reverse("monolith_api:sub_manifest_pkg_info", args=(9999,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_sub_manifest_pkg_info_permission_denied(self):
        response = self.get(reverse("monolith_api:sub_manifest_pkg_info", args=(9999,)))
        self.assertEqual(response.status_code, 403)

    def test_get_sub_manifest_pkg_info_not_found(self):
        self._set_permissions("monolith.view_submanifestpkginfo")
        response = self.get(reverse("monolith_api:sub_manifest_pkg_info", args=(9999,)))
        self.assertEqual(response.status_code, 404)

    def test_get_sub_manifest_pkg_info(self):
        sub_manifest_pkg_info = self.force_sub_manifest_pkg_info()
        self._set_permissions("monolith.view_submanifestpkginfo")
        response = self.get(reverse("monolith_api:sub_manifest_pkg_info", args=(sub_manifest_pkg_info.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            'id': sub_manifest_pkg_info.pk,
            'sub_manifest': sub_manifest_pkg_info.sub_manifest.pk,
            'key': 'managed_installs',
            'pkg_info_name': sub_manifest_pkg_info.pkg_info_name.name,
            'featured_item': False,
            'condition': None,
            'shard_modulo': 100,
            'default_shard': 100,
            'excluded_tags': [],
            'tag_shards': [],
            'created_at': sub_manifest_pkg_info.created_at.isoformat(),
            'updated_at': sub_manifest_pkg_info.updated_at.isoformat(),
        })

    # create sub manifest pkg info

    def test_create_sub_manifest_pkg_info_unauthorized(self):
        response = self._post_json_data(reverse("monolith_api:sub_manifest_pkg_infos"), include_token=False, data={})
        self.assertEqual(response.status_code, 401)

    def test_create_sub_manifest_pkg_info_permission_denied(self):
        response = self._post_json_data(reverse("monolith_api:sub_manifest_pkg_infos"), data={})
        self.assertEqual(response.status_code, 403)

    def test_create_sub_manifest_pkg_info_fields_empty(self):
        self._set_permissions("monolith.add_submanifestpkginfo")
        response = self._post_json_data(reverse("monolith_api:sub_manifest_pkg_infos"), data={})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            'sub_manifest': ['This field is required.'],
            'key': ['This field is required.'],
            'pkg_info_name': ['This field is required.'],
            'excluded_tags': ['This field is required.'],
            'tag_shards': ['This field is required.'],
        })

    def test_create_sub_manifest_pkg_info_unknown_pkg_info_name(self):
        self._set_permissions("monolith.add_submanifestpkginfo")
        sub_manifest = self.force_sub_manifest()
        response = self._post_json_data(reverse("monolith_api:sub_manifest_pkg_infos"), data={
            'sub_manifest': sub_manifest.pk,
            'pkg_info_name': get_random_string(12),
            'featured_item': True,
            'key': 'managed_installs',
            'excluded_tags': [],
            'tag_shards': []
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'pkg_info_name': ['Unknown PkgInfo name']})

    def test_create_sub_manifest_pkg_info_scoping_errors(self):
        self._set_permissions("monolith.add_submanifestpkginfo")
        sub_manifest = self.force_sub_manifest()
        pkg_info_name = self.force_pkg_info_name()
        tag1 = Tag.objects.create(name=get_random_string(12))
        tag2 = Tag.objects.create(name=get_random_string(12))
        response = self._post_json_data(reverse("monolith_api:sub_manifest_pkg_infos"), data={
            'sub_manifest': sub_manifest.pk,
            'pkg_info_name': pkg_info_name.name,
            'key': 'managed_installs',
            'default_shard': 6,  # > shard_modulo
            'shard_modulo': 5,
            'excluded_tags': [tag2.pk],
            'tag_shards': [
                {'tag': tag1.pk, 'shard': 6},  # shard > shard_modulo
                {'tag': tag1.pk, 'shard': 1},  # duplicated
                {'tag': tag2.pk, 'shard': 2},  # also in excluded_tags
            ]
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
                response.json(),
                {'default_shard': ['cannot be greater than shard_modulo'],
                 'tag_shards': [f'{tag1.pk}: shard > shard_modulo',
                                f'{tag1.pk}: duplicated',
                                f'{tag2.pk}: cannot be excluded']}
        )

    def test_create_sub_manifest_pkg_info(self):
        self._set_permissions("monolith.add_submanifestpkginfo")
        sub_manifest = self.force_sub_manifest()
        pkg_info_name = self.force_pkg_info_name()
        response = self._post_json_data(reverse("monolith_api:sub_manifest_pkg_infos"), data={
            'sub_manifest': sub_manifest.pk,
            'pkg_info_name': pkg_info_name.name,
            'featured_item': True,
            'key': 'managed_installs',
            'excluded_tags': [],
            'tag_shards': []
        })
        self.assertEqual(response.status_code, 201)
        sub_manifest_pkg_info = SubManifestPkgInfo.objects.get(sub_manifest=sub_manifest,
                                                               pkg_info_name=pkg_info_name)
        self.assertEqual(response.json(), {
            'id': sub_manifest_pkg_info.pk,
            'sub_manifest': sub_manifest_pkg_info.sub_manifest.pk,
            'key': 'managed_installs',
            'pkg_info_name': sub_manifest_pkg_info.pkg_info_name.name,
            'featured_item': True,
            'condition': None,
            'shard_modulo': 100,
            'default_shard': 100,
            'excluded_tags': [],
            'tag_shards': [],
            'created_at': sub_manifest_pkg_info.created_at.isoformat(),
            'updated_at': sub_manifest_pkg_info.updated_at.isoformat(),
        })
        self.assertEqual(sub_manifest_pkg_info.key, "managed_installs")
        self.assertTrue(sub_manifest_pkg_info.featured_item)
        self.assertEqual(sub_manifest_pkg_info.options,
                         {"shards": {"modulo": 100, "default": 100}})

    # update sub manifest pkg info

    def test_update_sub_manifest_pkg_info_unauthorized(self):
        response = self._put_json_data(reverse("monolith_api:sub_manifest_pkg_info", args=(9999,)),
                                       include_token=False, data={})
        self.assertEqual(response.status_code, 401)

    def test_update_sub_manifest_pkg_info_permission_denied(self):
        response = self._put_json_data(reverse("monolith_api:sub_manifest_pkg_info", args=(9999,)), data={})
        self.assertEqual(response.status_code, 403)

    def test_update_sub_manifest_pkg_info_not_found(self):
        self._set_permissions("monolith.change_submanifestpkginfo")
        response = self._put_json_data(reverse("monolith_api:sub_manifest_pkg_info", args=(9999,)), data={})
        self.assertEqual(response.status_code, 404)

    def test_update_sub_manifest_pkg_info(self):
        sub_manifest_pkg_info = self.force_sub_manifest_pkg_info()
        self._set_permissions("monolith.change_submanifestpkginfo")
        new_sub_manifest = self.force_sub_manifest()
        new_pkg_info_name = self.force_pkg_info_name()
        new_condition = self.force_condition()
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        response = self._put_json_data(
            reverse("monolith_api:sub_manifest_pkg_info", args=(sub_manifest_pkg_info.pk,)),
            data={
                'sub_manifest': new_sub_manifest.pk,
                'pkg_info_name': new_pkg_info_name.name,
                'key': 'managed_installs',
                'condition': new_condition.pk,
                'excluded_tags': [excluded_tag.pk],
                'shard_modulo': 42,
                'default_shard': 0,
                'tag_shards': [
                    {"tag": shard_tag.pk, "shard": 17},
                ]
            }
        )
        self.assertEqual(response.status_code, 200)
        test_sub_manifest_pkg_info = SubManifestPkgInfo.objects.get(sub_manifest=new_sub_manifest,
                                                                    pkg_info_name=new_pkg_info_name)
        self.assertEqual(sub_manifest_pkg_info, test_sub_manifest_pkg_info)
        self.assertEqual(response.json(), {
            'id': sub_manifest_pkg_info.pk,
            'sub_manifest': new_sub_manifest.pk,
            'key': 'managed_installs',
            'pkg_info_name': new_pkg_info_name.name,
            'featured_item': False,
            'condition': new_condition.pk,
            'shard_modulo': 42,
            'default_shard': 0,
            'excluded_tags': [excluded_tag.pk],
            'tag_shards': [
                {"tag": shard_tag.pk, "shard": 17},
            ],
            'created_at': test_sub_manifest_pkg_info.created_at.isoformat(),
            'updated_at': test_sub_manifest_pkg_info.updated_at.isoformat(),
        })
        self.assertEqual(test_sub_manifest_pkg_info.condition, new_condition)
        self.assertEqual(
            test_sub_manifest_pkg_info.options,
            {"shards": {"modulo": 42, "default": 0, "tags": {shard_tag.name: 17}},
             "excluded_tags": [excluded_tag.name]}
        )

    # delete sub manifest pkg info

    def test_delete_sub_manifest_pkg_info_unauthorized(self):
        response = self.delete(reverse("monolith_api:sub_manifest_pkg_info", args=(9999,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_sub_manifest_pkg_info_permission_denied(self):
        response = self.delete(reverse("monolith_api:sub_manifest_pkg_info", args=(9999,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_sub_manifest_pkg_info_not_found(self):
        self._set_permissions("monolith.delete_submanifestpkginfo")
        response = self.delete(reverse("monolith_api:sub_manifest_pkg_info", args=(9999,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_sub_manifest_pkg_info(self):
        sub_manifest_pkg_info = self.force_sub_manifest_pkg_info()
        self._set_permissions("monolith.delete_submanifestpkginfo")
        response = self.delete(reverse("monolith_api:sub_manifest_pkg_info", args=(sub_manifest_pkg_info.pk,)))
        self.assertEqual(response.status_code, 204)

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
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.monolith.models import CacheServer, Manifest


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

    def _post_json_data(self, url, data, include_token=True, ip=None):
        content_type = "application/json"
        data = json.dumps(data)
        return self._post_data(url, data, content_type, include_token, ip)

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

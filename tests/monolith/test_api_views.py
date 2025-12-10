from datetime import datetime
from functools import reduce
import json
import operator
import plistlib
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import APIToken, User
from zentral.conf import settings
from zentral.contrib.inventory.models import MetaBusinessUnit, Tag
from zentral.contrib.inventory.serializers import EnrollmentSecretSerializer
from zentral.contrib.monolith.events import MonolithSyncCatalogsRequestEvent
from zentral.contrib.monolith.models import (CacheServer, Catalog, Condition, Enrollment,
                                             Manifest, ManifestCatalog, ManifestSubManifest,
                                             PkgInfo, PkgInfoName,
                                             Repository,
                                             SubManifest, SubManifestPkgInfo)
from zentral.contrib.monolith.repository_backends import load_repository_backend
from zentral.core.events.base import AuditEvent
from .utils import (CLOUDFRONT_PRIVKEY_PEM,
                    force_catalog, force_condition,
                    force_enrollment,
                    force_manifest,
                    force_name, force_pkg_info,
                    force_repository,
                    force_sub_manifest, force_sub_manifest_pkg_info)


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
        _, cls.api_key = APIToken.objects.update_or_create_for_user(user=cls.service_account)
        # mbu
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
        cls.mbu.create_enrollment_business_unit()

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

    # list repositories

    def test_get_repositories_unauthorized(self):
        response = self.get(reverse("monolith_api:repositories"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_repositories_permission_denied(self):
        response = self.get(reverse("monolith_api:repositories"))
        self.assertEqual(response.status_code, 403)

    def test_get_repositories_filter_by_name_not_found(self):
        force_repository()
        self._set_permissions("monolith.view_repository")
        response = self.get(reverse("monolith_api:repositories"), {"name": "foo"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_get_repositories_filter_by_name(self):
        force_repository()
        repository = force_repository(virtual=True)
        self._set_permissions("monolith.view_repository")
        response = self.get(reverse("monolith_api:repositories"), {"name": repository.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': repository.pk,
            'provisioning_uid': None,
            'backend': 'VIRTUAL',
            'azure_kwargs': None,
            's3_kwargs': None,
            'name': repository.name,
            'created_at': repository.created_at.isoformat(),
            'updated_at': repository.updated_at.isoformat(),
            'meta_business_unit': None,
            'client_resources': [],
            'icon_hashes': {},
            'last_synced_at': None,
        }])

    def test_get_repositories(self):
        self._set_permissions("monolith.view_repository")
        repository = force_repository(mbu=self.mbu)
        response = self.get(reverse("monolith_api:repositories"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': repository.pk,
            'provisioning_uid': None,
            'backend': 'S3',
            'azure_kwargs': None,
            's3_kwargs': repository.get_backend_kwargs(),
            'name': repository.name,
            'created_at': repository.created_at.isoformat(),
            'updated_at': repository.updated_at.isoformat(),
            'meta_business_unit': self.mbu.pk,
            'client_resources': [],
            'icon_hashes': {},
            'last_synced_at': None,
        }])

    def test_get_provisioned_repositories(self):
        self._set_permissions("monolith.view_repository")
        provisioning_uid = get_random_string(12)
        repository = force_repository(mbu=self.mbu, provisioning_uid=provisioning_uid)
        response = self.get(reverse("monolith_api:repositories"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': repository.pk,
            'provisioning_uid': provisioning_uid,
            # no backend, azure_kwargs and s3_kwargs
            'name': repository.name,
            'created_at': repository.created_at.isoformat(),
            'updated_at': repository.updated_at.isoformat(),
            'meta_business_unit': self.mbu.pk,
            'client_resources': [],
            'icon_hashes': {},
            'last_synced_at': None,
        }])

    # create repository

    def test_create_repository_unauthorized(self):
        response = self._post_json_data(reverse("monolith_api:repositories"), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_repository_permission_denied(self):
        response = self._post_json_data(reverse("monolith_api:repositories"), {})
        self.assertEqual(response.status_code, 403)

    def test_create_s3_repository_missing_bucket(self):
        self._set_permissions("monolith.add_repository")
        response = self._post_json_data(
            reverse("monolith_api:repositories"),
            {"name": get_random_string(12),
             "meta_business_unit": self.mbu.pk,
             "backend": "S3",
             "s3_kwargs": {}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'s3_kwargs': {'bucket': ['This field is required.']}})

    def test_create_s3_repository_invalid_privkey(self):
        self._set_permissions("monolith.add_repository")
        response = self._post_json_data(
            reverse("monolith_api:repositories"),
            {"name": get_random_string(12),
             "meta_business_unit": self.mbu.pk,
             "backend": "S3",
             "s3_kwargs": {"bucket": get_random_string(12),
                           "cloudfront_privkey_pem": "YADA"}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'s3_kwargs': {'cloudfront_privkey_pem': ['Invalid private key.']}})

    def test_create_s3_repository_missing_cloudfront_domain_key_id(self):
        self._set_permissions("monolith.add_repository")
        response = self._post_json_data(
            reverse("monolith_api:repositories"),
            {"name": get_random_string(12),
             "meta_business_unit": self.mbu.pk,
             "backend": "S3",
             "s3_kwargs": {"bucket": get_random_string(12),
                           "cloudfront_privkey_pem": CLOUDFRONT_PRIVKEY_PEM}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'s3_kwargs': {
                'cloudfront_domain': ['This field is required when configuring Cloudfront.'],
                'cloudfront_key_id': ['This field is required when configuring Cloudfront.']
             }}
        )

    def test_create_s3_repository_missing_cloudfront_key_id_privkey_pem(self):
        self._set_permissions("monolith.add_repository")
        response = self._post_json_data(
            reverse("monolith_api:repositories"),
            {"name": get_random_string(12),
             "meta_business_unit": self.mbu.pk,
             "backend": "S3",
             "s3_kwargs": {"bucket": get_random_string(12),
                           "cloudfront_domain": "yolo.cloudfront.net"}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'s3_kwargs': {
                'cloudfront_key_id': ['This field is required when configuring Cloudfront.'],
                'cloudfront_privkey_pem': ['This field is required when configuring Cloudfront.'],
             }}
        )

    def test_create_virtual_repository_bad_backend(self):
        self._set_permissions("monolith.add_repository")
        response = self._post_json_data(
            reverse("monolith_api:repositories"),
            {"name": get_random_string(12),
             "meta_business_unit": self.mbu.pk,
             "backend": "YOLO"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'backend': ['"YOLO" is not a valid choice.']}
        )

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_s3_repository(self, post_event, send_notification):
        self._set_permissions("monolith.add_repository")
        name = get_random_string(12)
        bucket = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self._post_json_data(
                reverse("monolith_api:repositories"),
                {"name": name,
                 "meta_business_unit": self.mbu.pk,
                 "backend": "S3",
                 "s3_kwargs": {"bucket": bucket,
                               "access_key_id": "",  # blank values OK
                               "secret_access_key": "",
                               "signature_version": "",
                               "cloudfront_privkey_pem": "",
                               }},
            )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        repository = Repository.objects.get(name=name)
        self.assertEqual(response.json(), {
            'id': repository.pk,
            'provisioning_uid': None,
            'backend': 'S3',
            'azure_kwargs': None,
            's3_kwargs': {"bucket": bucket},
            'name': repository.name,
            'created_at': repository.created_at.isoformat(),
            'updated_at': repository.updated_at.isoformat(),
            'meta_business_unit': self.mbu.pk,
            'client_resources': [],
            'icon_hashes': {},
            'last_synced_at': None,
        })
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "monolith.repository",
                 "pk": str(repository.pk),
                 "new_value": {
                     "pk": repository.pk,
                     "name": name,
                     "meta_business_unit": {"pk": self.mbu.pk, "name": self.mbu.name},
                     "backend": "S3",
                     "backend_kwargs": {"bucket": bucket},
                     "created_at": repository.created_at,
                     "updated_at": repository.updated_at,
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"monolith_repository": [str(repository.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])
        send_notification.assert_called_once_with("monolith.repository", str(repository.pk))
        repository_backend = load_repository_backend(repository)
        self.assertEqual(repository_backend.prefix, "")
        self.assertEqual(repository_backend.credentials, {})
        self.assertIsNone(repository_backend.assume_role_arn)
        self.assertEqual(repository_backend.signature_version, "s3v4")
        self.assertIsNone(repository_backend.cloudfront_signer)

    def test_create_azure_repository_missing_info(self):
        self._set_permissions("monolith.add_repository")
        response = self._post_json_data(
            reverse("monolith_api:repositories"),
            {"name": get_random_string(12),
             "meta_business_unit": self.mbu.pk,
             "backend": "AZURE",
             "azure_kwargs": {}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'azure_kwargs': {'storage_account': ['This field is required.'],
                                                            'container': ['This field is required.']}})

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_azure_repository(self, post_event, send_notification):
        self._set_permissions("monolith.add_repository")
        name = get_random_string(12)
        storage_account = get_random_string(12)
        container = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self._post_json_data(
                reverse("monolith_api:repositories"),
                {"name": name,
                 "meta_business_unit": self.mbu.pk,
                 "backend": "AZURE",
                 "azure_kwargs": {"storage_account": storage_account,
                                  "container": container,
                                  "client_id": "",
                                  "tenant_id": "",
                                  "client_secret": "",
                                  }},
            )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        repository = Repository.objects.get(name=name)
        self.assertEqual(response.json(), {
            'id': repository.pk,
            'provisioning_uid': None,
            'backend': 'AZURE',
            'azure_kwargs': {"storage_account": storage_account,
                             "container": container},
            's3_kwargs': None,
            'name': repository.name,
            'created_at': repository.created_at.isoformat(),
            'updated_at': repository.updated_at.isoformat(),
            'meta_business_unit': self.mbu.pk,
            'client_resources': [],
            'icon_hashes': {},
            'last_synced_at': None,
        })
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "monolith.repository",
                 "pk": str(repository.pk),
                 "new_value": {
                     "pk": repository.pk,
                     "name": name,
                     "meta_business_unit": {"pk": self.mbu.pk, "name": self.mbu.name},
                     "backend": "AZURE",
                     "backend_kwargs": {"storage_account": storage_account,
                                        "container": container},
                     "created_at": repository.created_at,
                     "updated_at": repository.updated_at,
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"monolith_repository": [str(repository.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])
        send_notification.assert_called_once_with("monolith.repository", str(repository.pk))
        repository_backend = load_repository_backend(repository)
        self.assertEqual(repository_backend.prefix, "")
        self.assertEqual(repository_backend._credential_kwargs, {})

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_virtual_repository(self, post_event, send_notification):
        self._set_permissions("monolith.add_repository")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self._post_json_data(
                reverse("monolith_api:repositories"),
                {"name": name,
                 "backend": "VIRTUAL"},
            )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        repository = Repository.objects.get(name=name)
        self.assertEqual(response.json(), {
            'id': repository.pk,
            'provisioning_uid': None,
            'backend': 'VIRTUAL',
            'azure_kwargs': None,
            's3_kwargs': None,
            'name': repository.name,
            'created_at': repository.created_at.isoformat(),
            'updated_at': repository.updated_at.isoformat(),
            'meta_business_unit': None,
            'client_resources': [],
            'icon_hashes': {},
            'last_synced_at': None,
        })
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "monolith.repository",
                 "pk": str(repository.pk),
                 "new_value": {
                     "pk": repository.pk,
                     "name": name,
                     "backend": "VIRTUAL",
                     "backend_kwargs": {},
                     "created_at": repository.created_at,
                     "updated_at": repository.updated_at,
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"monolith_repository": [str(repository.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])
        send_notification.assert_called_once_with("monolith.repository", str(repository.pk))

    def test_create_s3_repository_provisining_id_read_only(self):
        self._set_permissions("monolith.add_repository")
        name = get_random_string(12)
        provisioning_uid = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True):
            response = self._post_json_data(
                reverse("monolith_api:repositories"),
                {"name": name,
                 "provisioning_uid": provisioning_uid,
                 "backend": "S3",
                 "s3_kwargs": {"bucket": get_random_string(12)}},
            )
        self.assertEqual(response.status_code, 201)
        repository = Repository.objects.get(pk=response.json()["id"])
        self.assertEqual(repository.name, name)
        self.assertIsNone(repository.provisioning_uid)

    # get repository

    def test_get_repository_unauthorized(self):
        repository = force_repository()
        response = self.get(reverse("monolith_api:repository", args=(repository.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_repository_permission_denied(self):
        repository = force_repository()
        response = self.get(reverse("monolith_api:repository", args=(repository.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_repository(self):
        self._set_permissions("monolith.view_repository")
        repository = force_repository(mbu=self.mbu)
        response = self.get(reverse("monolith_api:repository", args=(repository.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            'id': repository.pk,
            'provisioning_uid': None,
            'backend': 'S3',
            'azure_kwargs': None,
            's3_kwargs': repository.get_backend_kwargs(),
            'name': repository.name,
            'created_at': repository.created_at.isoformat(),
            'updated_at': repository.updated_at.isoformat(),
            'meta_business_unit': self.mbu.pk,
            'client_resources': [],
            'icon_hashes': {},
            'last_synced_at': None,
        })

    # update repository

    def test_update_repository_unauthorized(self):
        repository = force_repository()
        response = self._post_json_data(reverse("monolith_api:repository", args=(repository.pk,)),
                                        {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_repository_permission_denied(self):
        repository = force_repository()
        response = self._post_json_data(reverse("monolith_api:repository", args=(repository.pk,)), {})
        self.assertEqual(response.status_code, 403)

    def test_update_provisioned_repository_cannot_be_updated(self):
        repository = force_repository(provisioning_uid=get_random_string(12))
        self._set_permissions("monolith.change_repository")
        response = self._put_json_data(
            reverse("monolith_api:repository", args=(repository.pk,)),
            {"name": "yolo",
             "backend": "S3",
             "s3_kwargs": {"bucket": "fomo"}}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ['This repository cannot be updated'])

    def test_update_s3_repository_bad_mbu(self):
        repository = force_repository()
        manifest = force_manifest()
        self.assertIsNone(repository.meta_business_unit)
        self.assertNotEqual(manifest.meta_business_unit, self.mbu)
        force_catalog(repository=repository, manifest=manifest)
        self._set_permissions("monolith.change_repository")
        response = self._put_json_data(
            reverse("monolith_api:repository", args=(repository.pk,)),
            {"name": get_random_string(12),
             "meta_business_unit": self.mbu.pk,
             "backend": "S3",
             "s3_kwargs": {"bucket": get_random_string(12)}}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'meta_business_unit': [
                f"Repository linked to manifest '{manifest}' which has a different business unit."
             ]}
        )

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_s3_repository(self, post_event, send_notification):
        repository = force_repository()
        manifest = force_manifest(mbu=self.mbu)
        self.assertEqual(manifest.version, 1)
        # two catalogs, only one manifest version bump!
        force_catalog(repository=repository, manifest=manifest)
        force_catalog(repository=repository, manifest=manifest)
        prev_value = repository.serialize_for_event()
        self._set_permissions("monolith.change_repository")
        new_name = get_random_string(12)
        new_bucket = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self._put_json_data(
                reverse("monolith_api:repository", args=(repository.pk,)),
                {"name": new_name,
                 "meta_business_unit": self.mbu.pk,
                 "backend": "S3",
                 "s3_kwargs": {
                     "bucket": new_bucket,
                     "region_name": "us-east2",
                     "prefix": "prefix",
                     "access_key_id": "11111111111111111111",
                     "secret_access_key": "22222222222222222222",
                     "assume_role_arn": "arn:aws:iam::123456789012:role/S3Access",
                     "signature_version": "s3v2",
                     "endpoint_url": "https://endpoint.example.com",
                     "cloudfront_domain": "yada.cloudfront.net",
                     "cloudfront_key_id": "YADA",
                     "cloudfront_privkey_pem": CLOUDFRONT_PRIVKEY_PEM}
                 },
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        repository2 = Repository.objects.get(name=new_name)
        self.assertEqual(repository, repository2)
        repository.refresh_from_db()
        self.assertEqual(response.json(), {
            'id': repository.pk,
            'provisioning_uid': None,
            'backend': 'S3',
            'azure_kwargs': None,
            's3_kwargs': {
                "bucket": new_bucket,
                "region_name": "us-east2",
                "prefix": "prefix",
                "access_key_id": "11111111111111111111",
                "secret_access_key": "22222222222222222222",
                "assume_role_arn": "arn:aws:iam::123456789012:role/S3Access",
                "signature_version": "s3v2",
                "endpoint_url": "https://endpoint.example.com",
                "cloudfront_domain": "yada.cloudfront.net",
                "cloudfront_key_id": "YADA",
                "cloudfront_privkey_pem": CLOUDFRONT_PRIVKEY_PEM
            },
            'name': new_name,
            'created_at': repository.created_at.isoformat(),
            'updated_at': repository.updated_at.isoformat(),
            'meta_business_unit': self.mbu.pk,
            'client_resources': [],
            'icon_hashes': {},
            'last_synced_at': None,
        })
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "monolith.repository",
                 "pk": str(repository.pk),
                 "prev_value": prev_value,
                 "new_value": {
                     "pk": repository.pk,
                     "name": new_name,
                     "meta_business_unit": {"pk": self.mbu.pk, "name": self.mbu.name},
                     "backend": "S3",
                     "backend_kwargs": {
                         "access_key_id": "11111111111111111111",
                         "assume_role_arn": "arn:aws:iam::123456789012:role/S3Access",
                         "bucket": new_bucket,
                         "cloudfront_domain": "yada.cloudfront.net",
                         "cloudfront_key_id": "YADA",
                         "cloudfront_privkey_pem_hash": "f42f0756e0d05ae8e6e63581e615d2d8"
                                                        "04c0f79b9f6bfb3cb7cfc5e9b6fc6a8f",
                         "endpoint_url": "https://endpoint.example.com",
                         "prefix": "prefix",
                         "region_name": "us-east2",
                         "secret_access_key_hash": "d70d4cbd04b6a3140c2ee642a40820abeacef01117ea9ce209de7c72452abe21",
                         "signature_version": "s3v2",
                     },
                     "created_at": repository.created_at,
                     "updated_at": repository.updated_at,
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"monolith_repository": [str(repository.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])
        send_notification.assert_called_once_with("monolith.repository", str(repository.pk))
        repository_backend = load_repository_backend(repository)
        self.assertEqual(repository_backend.name, new_name)
        self.assertEqual(repository_backend.bucket, new_bucket)
        self.assertEqual(repository_backend.region_name, "us-east2")
        self.assertEqual(repository_backend.prefix, "prefix")
        self.assertEqual(
            repository_backend.credentials,
            {'aws_access_key_id': '11111111111111111111',
             'aws_secret_access_key': '22222222222222222222'}
        )
        self.assertEqual(
            repository_backend.assume_role_arn,
            "arn:aws:iam::123456789012:role/S3Access",
        )
        self.assertEqual(repository_backend.signature_version, "s3v2")
        self.assertEqual(repository_backend.endpoint_url, "https://endpoint.example.com")
        self.assertEqual(repository_backend.cloudfront_domain, "yada.cloudfront.net")
        self.assertEqual(repository_backend.cloudfront_key_id, "YADA")
        self.assertEqual(repository_backend.cloudfront_privkey_pem, CLOUDFRONT_PRIVKEY_PEM)
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 2)  # only one bump

    def test_update_s3_repository_provisioning_id_read_only(self):
        repository = force_repository()
        self._set_permissions("monolith.change_repository")
        new_name = get_random_string(12)
        new_bucket = get_random_string(12)
        response = self._put_json_data(
            reverse("monolith_api:repository", args=(repository.pk,)),
            {"name": new_name,
             "provisioning_uid": get_random_string(12),
             "backend": "S3",
             "s3_kwargs": {"bucket": new_bucket}},
        )
        self.assertEqual(response.status_code, 200)
        repository2 = Repository.objects.get(pk=response.json()["id"])
        self.assertEqual(repository2, repository)
        self.assertEqual(repository2.name, new_name)
        self.assertEqual(repository2.get_backend_kwargs(), {"bucket": new_bucket})
        self.assertIsNone(repository2.provisioning_uid)

    # delete repository

    def test_delete_repository_unauthorized(self):
        repository = force_repository()
        response = self.delete(reverse("monolith_api:repository", args=(repository.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_repository_permission_denied(self):
        repository = force_repository()
        response = self.delete(reverse("monolith_api:repository", args=(repository.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_linked_repository_cannot_be_deleted(self):
        repository = force_repository()
        manifest = force_manifest()
        force_catalog(repository=repository, manifest=manifest)
        self._set_permissions("monolith.delete_repository")
        response = self.delete(reverse("monolith_api:repository", args=(repository.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ['This repository cannot be deleted'])

    def test_delete_provisioned_repository_cannot_be_deleted(self):
        repository = force_repository(provisioning_uid=get_random_string(12))
        self._set_permissions("monolith.delete_repository")
        response = self.delete(reverse("monolith_api:repository", args=(repository.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ['This repository cannot be deleted'])

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_s3_repository(self, post_event, send_notification):
        repository = force_repository()
        prev_value = repository.serialize_for_event()
        self._set_permissions("monolith.delete_repository")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("monolith_api:repository", args=(repository.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "monolith.repository",
                 "pk": str(repository.pk),
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"monolith_repository": [str(repository.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])
        send_notification.assert_called_once_with("monolith.repository", str(repository.pk))

    # sync repository

    def test_sync_repository_unauthorized(self):
        repository = force_repository()
        response = self._post_json_data(reverse("monolith_api:sync_repository", args=(repository.pk,)),
                                        {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_sync_repository_permission_denied(self):
        repository = force_repository()
        response = self._post_json_data(reverse("monolith_api:sync_repository", args=(repository.pk,)), {})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.contrib.monolith.repository_backends.s3.S3Repository.sync_catalogs")
    def test_sync_repository_internal_server_error(self, sync_catalogs):
        sync_catalogs.side_effect = Exception("yolo")
        repository = force_repository()
        self._set_permissions("monolith.sync_repository")
        response = self._post_json_data(reverse("monolith_api:sync_repository", args=(repository.pk,)), {})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json(), {"status": 1, "error": "yolo"})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("zentral.contrib.monolith.repository_backends.s3.S3Repository.get_all_catalog_content")
    @patch("zentral.contrib.monolith.repository_backends.s3.S3Repository.get_icon_hashes_content")
    @patch("zentral.contrib.monolith.repository_backends.s3.S3Repository.iter_client_resources")
    def test_sync_repository(
        self,
        iter_client_resources,
        get_icon_hashes_content,
        get_all_catalog_content,
        post_event
    ):
        repository = force_repository()
        catalog_name = get_random_string(12)
        pkg_info_name = get_random_string(12)
        iter_client_resources.return_value = ["site_default.zip",]
        get_icon_hashes_content.return_value = plistlib.dumps({
            f"{pkg_info_name}.png": "a" * 64
        })
        get_all_catalog_content.return_value = plistlib.dumps([
            {"catalogs": [catalog_name],
             "name": pkg_info_name,
             "version": "1.0"}
        ])
        self._set_permissions("monolith.sync_repository")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self._post_json_data(reverse("monolith_api:sync_repository", args=(repository.pk,)), {})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {"status": 0})
        pkg_infos = PkgInfo.objects.filter(name__name=pkg_info_name)
        self.assertEqual(pkg_infos.count(), 1)
        pkg_info = pkg_infos.first()
        self.assertEqual(pkg_info.repository, repository)
        self.assertEqual(list(c.name for c in pkg_info.catalogs.filter(repository=repository)),
                         [catalog_name])
        repository.refresh_from_db()
        self.assertEqual(repository.client_resources, ["site_default.zip"])
        self.assertEqual(repository.icon_hashes, {f"icon.{pkg_info.pk}.{pkg_info_name}.png": "a" * 64})
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(len(post_event.call_args_list), 4)
        mscr_evt = post_event.call_args_list[0].args[0]
        self.assertIsInstance(mscr_evt, MonolithSyncCatalogsRequestEvent)
        mca_evt = post_event.call_args_list[1].args[0]
        self.assertIsInstance(mca_evt, AuditEvent)
        self.assertEqual(mca_evt.payload["action"], "created")
        self.assertEqual(mca_evt.payload["object"]["model"], "monolith.catalog")
        self.assertEqual(mca_evt.payload["object"]["pk"],
                         str(Catalog.objects.get(name=catalog_name).pk))
        mpina_evt = post_event.call_args_list[2].args[0]
        self.assertIsInstance(mpina_evt, AuditEvent)
        self.assertEqual(mpina_evt.payload["action"], "created")
        self.assertEqual(mpina_evt.payload["object"]["model"], "monolith.pkginfoname")
        self.assertEqual(mpina_evt.payload["object"]["pk"],
                         str(PkgInfoName.objects.get(name=pkg_info_name).pk))
        mpia_evt = post_event.call_args_list[3].args[0]
        self.assertIsInstance(mpia_evt, AuditEvent)
        self.assertEqual(mpia_evt.payload["action"], "created")
        self.assertEqual(mpia_evt.payload["object"]["model"], "monolith.pkginfo")
        self.assertEqual(mpia_evt.payload["object"]["pk"],
                         str(PkgInfo.objects.get(name__name=pkg_info_name,
                                                 version="1.0").pk))

    # update cache server

    def test_update_cache_server_unauthorized(self):
        manifest = force_manifest()
        response = self._post_json_data(reverse("monolith_api:update_cache_server", args=(manifest.pk,)),
                                        {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_cache_server_permission_denied(self):
        manifest = force_manifest()
        response = self._post_json_data(reverse("monolith_api:update_cache_server", args=(manifest.pk,)), {})
        self.assertEqual(response.status_code, 403)

    def test_update_cache_server(self):
        self._set_permissions("monolith.change_manifest", "monolith.add_cacheserver", "monolith.change_cacheserver")
        name = get_random_string(12)
        ip_address = "129.2.1.1"
        manifest = force_manifest()
        response = self._post_json_data(reverse("monolith_api:update_cache_server", args=(manifest.pk,)),
                                        {"name": name,
                                         "base_url": "https://example.com"},
                                        ip=ip_address)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": 0})
        cache_server = CacheServer.objects.get(manifest=manifest, name=name)
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
            force_manifest()
        self._set_permissions("monolith.view_manifest")
        manifest = force_manifest()
        response = self.get(reverse("monolith_api:manifests"), {"name": manifest.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': manifest.pk,
            'name': manifest.name,
            'version': 1,
            'created_at': manifest.created_at.isoformat(),
            'updated_at': manifest.updated_at.isoformat(),
            'meta_business_unit': manifest.meta_business_unit.pk
        }])

    def test_get_manifests_filter_by_meta_business_unit_id(self):
        self._set_permissions("monolith.view_manifest")
        manifest = force_manifest(mbu=self.mbu)
        response = self.get(reverse("monolith_api:manifests"),
                            {"meta_business_unit_id": self.mbu.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': manifest.pk,
            'name': manifest.name,
            'version': 1,
            'created_at': manifest.created_at.isoformat(),
            'updated_at': manifest.updated_at.isoformat(),
            'meta_business_unit': manifest.meta_business_unit.pk
        }])

    def test_get_manifests(self):
        self._set_permissions("monolith.view_manifest")
        manifest = force_manifest()
        response = self.get(reverse("monolith_api:manifests"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': manifest.pk,
            'name': manifest.name,
            'version': 1,
            'created_at': manifest.created_at.isoformat(),
            'updated_at': manifest.updated_at.isoformat(),
            'meta_business_unit': manifest.meta_business_unit.pk
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
        manifest = force_manifest()
        response = self.get(reverse("monolith_api:manifest", args=(manifest.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            'id': manifest.pk,
            'name': manifest.name,
            'version': 1,
            'created_at': manifest.created_at.isoformat(),
            'updated_at': manifest.updated_at.isoformat(),
            'meta_business_unit': manifest.meta_business_unit.pk
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

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_manifest(self, post_event):
        self._set_permissions("monolith.add_manifest")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self._post_json_data(reverse("monolith_api:manifests"), data={
                'name': name,
                'meta_business_unit': self.mbu.pk
            })
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        manifest = Manifest.objects.get(name=name)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "monolith.manifest",
                 "pk": str(manifest.pk),
                 "new_value": {
                    "pk": manifest.pk,
                    "name": name,
                    "version": 1,
                    "created_at": manifest.created_at,
                    "updated_at": manifest.updated_at,
                    "meta_business_unit": self.mbu.serialize_for_event(keys_only=True)
                 }
             }}
        )
        self.assertEqual(response.json(), {
            'id': manifest.pk,
            'name': name,
            'version': 1,
            'created_at': manifest.created_at.isoformat(),
            'updated_at': manifest.updated_at.isoformat(),
            'meta_business_unit': self.mbu.pk
        })
        self.assertEqual(manifest.name, name)
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"monolith_manifest": [str(manifest.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])

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
        manifest = force_manifest()
        response = self._put_json_data(reverse("monolith_api:manifest", args=(manifest.pk,)), data={
            'name': '',
            'meta_business_unit': ''
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            'name': ['This field may not be blank.'],
            'meta_business_unit': ['This field may not be null.']
        })

    def test_update_manifest_invalid_meta_business_unit(self):
        manifest = force_manifest()
        self._set_permissions("monolith.change_manifest")
        response = self._put_json_data(reverse("monolith_api:manifest", args=(manifest.pk,)), data={
            'name': 'foo',
            'meta_business_unit': 9999
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            'meta_business_unit': ['Invalid pk "9999" - object does not exist.']
        })

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_manifest(self, post_event):
        manifest = force_manifest(self.mbu)
        prev_name = manifest.name
        prev_updated_at = manifest.updated_at
        new_name = get_random_string(12)
        self._set_permissions("monolith.change_manifest")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self._put_json_data(reverse("monolith_api:manifest", args=(manifest.pk,)), data={
                'name': new_name,
                'meta_business_unit': self.mbu.pk
            })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        manifest.refresh_from_db()
        self.assertEqual(manifest.name, new_name)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload, {
                "action": "updated",
                "object": {
                    "model": "monolith.manifest",
                    "pk": str(manifest.pk),
                    "prev_value": {
                        "pk": manifest.pk,
                        "name": prev_name,
                        "version": 1,
                        "created_at": manifest.created_at,
                        "updated_at": prev_updated_at,
                        "meta_business_unit": self.mbu.serialize_for_event(keys_only=True)
                    },
                    "new_value": {
                        "pk": manifest.pk,
                        "name": new_name,
                        "version": 1,
                        "created_at": manifest.created_at,
                        "updated_at": manifest.updated_at,
                        "meta_business_unit": self.mbu.serialize_for_event(keys_only=True)
                    }
                }
            }
        )
        self.assertEqual(response.json(), {
            'id': manifest.pk,
            'name': new_name,
            'version': 1,
            'created_at': manifest.created_at.isoformat(),
            'updated_at': manifest.updated_at.isoformat(),
            'meta_business_unit': self.mbu.pk
        })
        self.assertEqual(manifest.name, new_name)
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"monolith_manifest": [str(manifest.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])

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
        manifest = force_manifest()
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
        force_catalog()
        catalog = force_catalog()
        self._set_permissions("monolith.view_catalog")
        response = self.get(reverse("monolith_api:catalogs"), {"name": catalog.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': catalog.pk,
            'repository': catalog.repository.pk,
            'name': catalog.name,
            'created_at': catalog.created_at.isoformat(),
            'updated_at': catalog.updated_at.isoformat(),
            'archived_at': None,
        }])

    def test_get_catalogs(self):
        catalog = force_catalog()
        self._set_permissions("monolith.view_catalog")
        response = self.get(reverse("monolith_api:catalogs"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': catalog.pk,
            'repository': catalog.repository.pk,
            'name': catalog.name,
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
        catalog = force_catalog(archived=True)
        self._set_permissions("monolith.view_catalog")
        response = self.get(reverse("monolith_api:catalog", args=(catalog.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            'id': catalog.pk,
            'repository': catalog.repository.pk,
            'name': catalog.name,
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
            'repository': ['This field is required.'],
            'name': ['This field is required.'],
        })

    def test_create_catalog_not_virtual_repository(self):
        self._set_permissions("monolith.add_catalog")
        name = get_random_string(12)
        repository = force_repository(virtual=False)
        response = self._post_json_data(reverse("monolith_api:catalogs"), data={
            'repository': repository.pk,
            'name': name,
            'archived_at': datetime.utcnow().isoformat(),
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            'repository': ['Not a virtual repository.'],
        })

    def test_create_catalog(self):
        self._set_permissions("monolith.add_catalog")
        name = get_random_string(12)
        repository = force_repository(virtual=True)
        response = self._post_json_data(reverse("monolith_api:catalogs"), data={
            'repository': repository.pk,
            'name': name,
            'archived_at': datetime.utcnow().isoformat(),
        })
        self.assertEqual(response.status_code, 201)
        catalog = Catalog.objects.get(name=name)
        self.assertEqual(response.json(), {
            'id': catalog.pk,
            'repository': repository.pk,
            'name': name,
            'created_at': catalog.created_at.isoformat(),
            'updated_at': catalog.updated_at.isoformat(),
            'archived_at': None  # read only
        })
        self.assertEqual(catalog.repository, repository)
        self.assertEqual(catalog.name, name)

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
        repository = force_repository(virtual=True)
        catalog = force_catalog(repository=repository)
        self._set_permissions("monolith.change_catalog")
        response = self._put_json_data(reverse("monolith_api:catalog", args=(catalog.pk,)), data={
            'name': '',
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {
            'repository': ['This field is required.'],
            'name': ['This field may not be blank.'],
        })

    def test_update_catalog_not_virtual_repository(self):
        repository = force_repository(virtual=False)
        catalog = force_catalog(repository=repository)
        self._set_permissions("monolith.change_catalog")
        response = self._put_json_data(reverse("monolith_api:catalog", args=(catalog.pk,)), data={
            'repository': catalog.repository.pk,
            'name': get_random_string(12),
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {"repository": ["Not a virtual repository."]}
        )

    def test_update_catalog_bad_mbu(self):
        manifest = force_manifest()
        repository = force_repository(mbu=manifest.meta_business_unit, virtual=True)
        catalog = force_catalog(repository=repository, manifest=manifest)
        new_repository = force_repository(mbu=MetaBusinessUnit.objects.create(name=get_random_string(12)),
                                          virtual=True)
        self._set_permissions("monolith.change_catalog")
        response = self._put_json_data(reverse("monolith_api:catalog", args=(catalog.pk,)), data={
            'repository': new_repository.pk,
            'name': get_random_string(12),
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {"repository": [
                "This catalog is included in manifests linked to different business units than this repository."
             ]}
        )

    def test_update_catalog(self):
        repository = force_repository(virtual=True)
        catalog = force_catalog(repository=repository)
        self._set_permissions("monolith.change_catalog")
        new_name = get_random_string(12)
        response = self._put_json_data(reverse("monolith_api:catalog", args=(catalog.pk,)), data={
            'repository': catalog.repository.pk,
            'name': new_name,
        })
        self.assertEqual(response.status_code, 200)
        catalog.refresh_from_db()
        self.assertEqual(response.json(), {
            'id': catalog.pk,
            'repository': catalog.repository.pk,
            'name': new_name,
            'created_at': catalog.created_at.isoformat(),
            'updated_at': catalog.updated_at.isoformat(),
            'archived_at': None
        })
        self.assertEqual(catalog.name, new_name)

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
        repository = force_repository(virtual=True)
        manifest = force_manifest()
        catalog = force_catalog(repository=repository, manifest=manifest)
        self._set_permissions("monolith.delete_catalog")
        response = self.delete(reverse("monolith_api:catalog", args=(catalog.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ['This catalog cannot be deleted'])

    def test_delete_catalog(self):
        repository = force_repository(virtual=True)
        catalog = force_catalog(repository=repository)
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
        force_condition()
        condition = force_condition()
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
        condition = force_condition()
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
        condition = force_condition()
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
        condition = force_condition()
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
        condition = force_condition()
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
        condition = force_condition()
        manifest = force_manifest()
        sub_manifest = force_sub_manifest(manifest=manifest)
        self.assertEqual(manifest.version, 1)
        SubManifestPkgInfo.objects.create(
            sub_manifest=sub_manifest,
            pkg_info_name=force_name(),
            condition=condition
        )
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
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 2)

    def test_update_condition_name_conflict(self):
        condition1 = force_condition()
        condition2 = force_condition()
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
        condition = force_condition()
        SubManifestPkgInfo.objects.create(
            sub_manifest=force_sub_manifest(),
            pkg_info_name=force_name(),
            condition=condition
        )
        self._set_permissions("monolith.delete_condition")
        response = self.delete(reverse("monolith_api:condition", args=(condition.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ['This condition cannot be deleted'])

    def test_delete_condition(self):
        condition = force_condition()
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
        manifest = force_manifest()
        response = self.get(reverse("monolith_api:enrollments"), {"manifest_id": manifest.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_get_enrollments_filter_by_manifest_id(self):
        enrollment, tags = force_enrollment(mbu=self.mbu, tag_count=1)
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
        enrollment, _ = force_enrollment(mbu=self.mbu)
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
        enrollment, _ = force_enrollment(mbu=self.mbu)
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
        manifest = force_manifest(mbu=self.mbu)
        self.assertEqual(manifest.version, 1)
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
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 2)

    def test_create_enrollment_mbu_conflict(self):
        self._set_permissions("monolith.add_enrollment")
        manifest = force_manifest()
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        response = self._post_json_data(reverse("monolith_api:enrollments"), data={
            'manifest': manifest.pk,
            'secret': {'meta_business_unit': mbu.pk}
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'secret.meta_business_unit': ['Must be the same as the manifest meta business unit.']}
        )

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
        enrollment, _ = force_enrollment(mbu=self.mbu, tag_count=2)
        enrollment_secret = enrollment.secret
        self.assertEqual(enrollment.secret.quota, None)
        self.assertEqual(enrollment.secret.serial_numbers, None)
        self.assertEqual(enrollment.secret.tags.count(), 2)
        manifest = enrollment.manifest
        self.assertEqual(manifest.version, 1)
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
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 2)

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
        enrollment, _ = force_enrollment(mbu=self.mbu)
        manifest = enrollment.manifest
        self.assertEqual(manifest.version, 1)
        self._set_permissions("monolith.delete_enrollment")
        response = self.delete(reverse("monolith_api:enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 204)
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 2)

    # enrollment plist

    def test_get_enrollment_plist_unauthorized(self):
        enrollment, _ = force_enrollment(mbu=self.mbu)
        response = self.get(reverse("monolith_api:enrollment_plist", args=(enrollment.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollment_plist_permission_denied(self):
        enrollment, _ = force_enrollment(mbu=self.mbu)
        response = self.get(reverse("monolith_api:enrollment_plist", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_plist_permission_denied_user(self):
        enrollment, _ = force_enrollment(mbu=self.mbu)
        self.client.force_login(self.user)
        response = self.client.get(reverse("monolith_api:enrollment_plist", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_plist(self):
        enrollment, _ = force_enrollment(mbu=self.mbu)
        self._set_permissions("monolith.view_enrollment")
        response = self.get(reverse("monolith_api:enrollment_plist", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/x-plist')
        self.assertEqual(response['Content-Disposition'],
                         f'attachment; filename="zentral_monolith_configuration.enrollment_{enrollment.pk}.plist"')
        self.assertEqual(int(response['Content-Length']), len(response.content))
        response = plistlib.loads(response.content)
        self.assertEqual(
            response,
            {'AdditionalHttpHeaders': [
                f'Authorization: Bearer {enrollment.secret.secret}',
                'X-Zentral-Serial-Number: $SERIALNUMBER',
                'X-Zentral-UUID: $UDID'
             ],
             'ClientIdentifier': '$SERIALNUMBER',
             'FollowHTTPRedirects': 'all',
             'SoftwareRepoURL': 'https://zentral/public/monolith/munki_repo'}
        )

    def test_get_enrollment_plist_user(self):
        enrollment, _ = force_enrollment(mbu=self.mbu)
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
        enrollment, _ = force_enrollment(mbu=self.mbu)
        response = self.get(
            reverse("monolith_api:enrollment_configuration_profile", args=(enrollment.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_enrollment_configuration_profile_permission_denied(self):
        enrollment, _ = force_enrollment(mbu=self.mbu)
        response = self.get(reverse("monolith_api:enrollment_configuration_profile", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_configuration_profile_permission_denied_user(self):
        enrollment, _ = force_enrollment(mbu=self.mbu)
        self.client.force_login(self.user)
        response = self.client.get(reverse("monolith_api:enrollment_configuration_profile", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_enrollment_configuration_profile(self):
        enrollment, _ = force_enrollment(mbu=self.mbu)
        self._set_permissions("monolith.view_enrollment")
        response = self.get(reverse("monolith_api:enrollment_configuration_profile", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/octet-stream')
        self.assertEqual(
            response['Content-Disposition'],
            f'attachment; filename="zentral_monolith_configuration.enrollment_{enrollment.pk}.mobileconfig"'
        )
        self.assertEqual(int(response['Content-Length']), len(response.content))
        response = plistlib.loads(response.content)
        self.assertEqual(
            response["PayloadContent"][0]["PayloadContent"]["ManagedInstalls"]["Forced"][0]["mcx_preference_settings"],
            {'AdditionalHttpHeaders': [
                f'Authorization: Bearer {enrollment.secret.secret}',
                'X-Zentral-Serial-Number: $SERIALNUMBER',
                'X-Zentral-UUID: $UDID'
             ],
             'ClientIdentifier': '$SERIALNUMBER',
             'FollowHTTPRedirects': 'all',
             'SoftwareRepoURL': 'https://zentral/public/monolith/munki_repo'}
        )

    def test_get_enrollment_configuration_profile_user(self):
        enrollment, _ = force_enrollment(mbu=self.mbu)
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
        manifest = force_manifest()
        response = self.get(reverse("monolith_api:manifest_catalogs"), {"manifest_id": manifest.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_get_manifest_catalogs_filter_by_manifest_id(self):
        manifest1 = force_manifest()
        force_catalog(manifest=manifest1)
        manifest2 = force_manifest()
        catalog = force_catalog(manifest=manifest2)
        self._set_permissions("monolith.view_manifestcatalog")
        response = self.get(reverse("monolith_api:manifest_catalogs"),
                            {"manifest_id": manifest2.id})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': manifest2.manifestcatalog_set.first().pk,
            'manifest': manifest2.id,
            'catalog': catalog.id,
            'tags': []
        }])

    def test_get_manifest_catalogs_filter_by_catalog_id(self):
        manifest = force_manifest()
        force_catalog(manifest=manifest)
        catalog = force_catalog(manifest=manifest)
        self._set_permissions("monolith.view_manifestcatalog")
        response = self.get(reverse("monolith_api:manifest_catalogs"),
                            {"catalog_id": catalog.id})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': manifest.manifestcatalog_set.get(catalog=catalog).pk,
            'manifest': manifest.id,
            'catalog': catalog.id,
            'tags': []
        }])

    def test_get_manifest_catalogs(self):
        manifest = force_manifest()
        catalog = force_catalog(manifest=manifest)
        self._set_permissions("monolith.view_manifestcatalog")
        response = self.get(reverse("monolith_api:manifest_catalogs"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': manifest.manifestcatalog_set.first().pk,
            'manifest': manifest.id,
            'catalog': catalog.id,
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
        tags = [Tag.objects.create(name=get_random_string(12))]
        manifest = force_manifest()
        catalog = force_catalog(manifest=manifest, tags=tags)
        manifest_catalog = manifest.manifestcatalog_set.first()
        self._set_permissions("monolith.view_manifestcatalog")
        response = self.get(reverse("monolith_api:manifest_catalog", args=(manifest_catalog.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            'id': manifest_catalog.pk,
            'manifest': manifest.id,
            'catalog': catalog.id,
            'tags': [tags[0].pk]
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
        manifest = force_manifest()
        self.assertEqual(manifest.version, 1)
        catalog = force_catalog()
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
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 2)

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
        manifest = force_manifest()
        tags = [Tag.objects.create(name=get_random_string(12))]
        catalog = force_catalog(manifest=manifest, tags=tags)
        manifest_catalog = manifest.manifestcatalog_set.first()
        self.assertEqual(manifest_catalog.tags.count(), 1)
        manifest = force_manifest()
        self.assertEqual(manifest.version, 1)
        catalog = force_catalog()
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
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 2)

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
        manifest = force_manifest()
        force_catalog(manifest=manifest)
        manifest_catalog = manifest.manifestcatalog_set.first()
        self.assertEqual(manifest.version, 1)
        self._set_permissions("monolith.delete_manifestcatalog")
        response = self.delete(reverse("monolith_api:manifest_catalog", args=(manifest_catalog.pk,)))
        self.assertEqual(response.status_code, 204)
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 2)

    # list manifest sub manifests

    def test_get_manifest_sub_manifests_unauthorized(self):
        response = self.get(reverse("monolith_api:manifest_sub_manifests"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_manifest_sub_manifests_permission_denied(self):
        response = self.get(reverse("monolith_api:manifest_sub_manifests"))
        self.assertEqual(response.status_code, 403)

    def test_get_manifest_sub_manifests_filter_by_manifest_id_not_found(self):
        self._set_permissions("monolith.view_manifestsubmanifest")
        manifest = force_manifest()
        response = self.get(reverse("monolith_api:manifest_sub_manifests"), {"manifest_id": manifest.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_get_manifest_sub_manifests_filter_by_manifest_id(self):
        manifest = force_manifest()
        force_sub_manifest()
        sub_manifest = force_sub_manifest(manifest=manifest)
        self._set_permissions("monolith.view_manifestsubmanifest")
        response = self.get(reverse("monolith_api:manifest_sub_manifests"),
                            {"manifest_id": manifest.id})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': manifest.manifestsubmanifest_set.filter(sub_manifest=sub_manifest).first().pk,
            'manifest': manifest.id,
            'sub_manifest': sub_manifest.id,
            'tags': []
        }])

    def test_get_manifest_sub_manifests_filter_by_sub_manifest_id(self):
        manifest = force_manifest()
        force_sub_manifest(manifest=manifest)
        sub_manifest = force_sub_manifest(manifest=manifest)
        manifest_sub_manifest = sub_manifest.manifestsubmanifest_set.first()
        self._set_permissions("monolith.view_manifestsubmanifest")
        response = self.get(reverse("monolith_api:manifest_sub_manifests"),
                            {"sub_manifest_id": sub_manifest.id})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': manifest_sub_manifest.pk,
            'manifest': manifest.id,
            'sub_manifest': sub_manifest.id,
            'tags': []
        }])

    def test_get_manifest_sub_manifests(self):
        manifest = force_manifest()
        sub_manifest = force_sub_manifest(manifest=manifest)
        manifest_sub_manifest = manifest.manifestsubmanifest_set.first()
        self._set_permissions("monolith.view_manifestsubmanifest")
        response = self.get(reverse("monolith_api:manifest_sub_manifests"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{
            'id': manifest_sub_manifest.pk,
            'manifest': manifest.id,
            'sub_manifest': sub_manifest.id,
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
        manifest = force_manifest()
        tags = [Tag.objects.create(name=get_random_string(12))]
        sub_manifest = force_sub_manifest(manifest=manifest, tags=tags)
        manifest_sub_manifest = sub_manifest.manifestsubmanifest_set.first()
        self._set_permissions("monolith.view_manifestsubmanifest")
        response = self.get(reverse("monolith_api:manifest_sub_manifest", args=(manifest_sub_manifest.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            'id': manifest_sub_manifest.pk,
            'manifest': manifest.id,
            'sub_manifest': sub_manifest.id,
            'tags': [t.pk for t in tags]
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
        manifest = force_manifest()
        self.assertEqual(manifest.version, 1)
        sub_manifest = force_sub_manifest()
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
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 2)

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
        manifest = force_manifest()
        tags = [Tag.objects.create(name=get_random_string(12))]
        force_sub_manifest(manifest=manifest, tags=tags)
        manifest_sub_manifest = manifest.manifestsubmanifest_set.first()
        self.assertEqual(manifest.version, 1)
        self.assertEqual(list(manifest_sub_manifest.tags.all()), tags)
        manifest = force_manifest()
        sub_manifest = force_sub_manifest()
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
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 2)

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
        manifest = force_manifest()
        force_sub_manifest(manifest=manifest)
        manifest_sub_manifest = manifest.manifestsubmanifest_set.first()
        self.assertEqual(manifest.version, 1)
        self._set_permissions("monolith.delete_manifestsubmanifest")
        response = self.delete(reverse("monolith_api:manifest_sub_manifest", args=(manifest_sub_manifest.pk,)))
        self.assertEqual(response.status_code, 204)
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 2)

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
        force_sub_manifest()
        sub_manifest = force_sub_manifest()
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
        sub_manifest = force_sub_manifest(mbu=self.mbu)
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
        sub_manifest = force_sub_manifest()
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

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_sub_manifest(self, post_event):
        self._set_permissions("monolith.add_submanifest")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self._post_json_data(reverse("monolith_api:sub_manifests"), data={
                'name': name
            })
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        sub_manifest = SubManifest.objects.get(name=name)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "monolith.submanifest",
                 "pk": str(sub_manifest.pk),
                 "new_value": {
                    "pk": sub_manifest.pk,
                    "name": name,
                    "description": "",
                    "created_at": sub_manifest.created_at,
                    "updated_at": sub_manifest.updated_at
                 }
             }}
        )
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
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"monolith_sub_manifest": [str(sub_manifest.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])

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

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_sub_manifest(self, post_event):
        sub_manifest = force_sub_manifest()
        self._set_permissions("monolith.change_submanifest")
        prev_value = sub_manifest.serialize_for_event()
        new_name = get_random_string(12)
        new_description = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self._put_json_data(reverse("monolith_api:sub_manifest", args=(sub_manifest.pk,)), data={
                'name': new_name,
                'description': new_description,
                'meta_business_unit': self.mbu.pk,
            })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        test_sub_manifest = SubManifest.objects.get(name=new_name)
        self.assertEqual(sub_manifest, test_sub_manifest)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload, {
                "action": "updated",
                "object": {
                    "model": "monolith.submanifest",
                    "pk": str(sub_manifest.pk),
                    "prev_value": prev_value,
                    "new_value": {
                        "pk": test_sub_manifest.pk,
                        "name": new_name,
                        "description": new_description,
                        "created_at": test_sub_manifest.created_at,
                        "updated_at": test_sub_manifest.updated_at,
                        "meta_business_unit": self.mbu.serialize_for_event(keys_only=True)
                    }
                }
            }
        )
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
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"monolith_sub_manifest": [str(sub_manifest.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])

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

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_sub_manifest(self, post_event):
        sub_manifest = force_sub_manifest()
        prev_value = sub_manifest.serialize_for_event()
        self._set_permissions("monolith.delete_submanifest")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("monolith_api:sub_manifest", args=(sub_manifest.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload, {
                "action": "deleted",
                "object": {
                    "model": "monolith.submanifest",
                    "pk": str(prev_value['pk']),
                    "prev_value": prev_value
                }
            }
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"monolith_sub_manifest": [str(prev_value['pk'])]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])

    # list sub manifest pkg infos

    def test_get_sub_manifest_pkg_infos_unauthorized(self):
        response = self.get(reverse("monolith_api:sub_manifest_pkg_infos"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_sub_manifest_pkg_infos_permission_denied(self):
        response = self.get(reverse("monolith_api:sub_manifest_pkg_infos"))
        self.assertEqual(response.status_code, 403)

    def test_get_sub_manifest_pkg_infos_filter_by_sub_manifest_id_not_found(self):
        self._set_permissions("monolith.view_submanifestpkginfo")
        sub_manifest = force_sub_manifest()
        response = self.get(reverse("monolith_api:sub_manifest_pkg_infos"), {"sub_manifest_id": sub_manifest.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_get_sub_manifest_pkg_infos_filter_by_sub_manifest_id(self):
        force_sub_manifest_pkg_info()
        sub_manifest_pkg_info = force_sub_manifest_pkg_info()
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
        sub_manifest_pkg_info = force_sub_manifest_pkg_info()
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
        sub_manifest_pkg_info = force_sub_manifest_pkg_info()
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
        sub_manifest = force_sub_manifest()
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
        sub_manifest = force_sub_manifest()
        pkg_info_name = force_name()
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

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_sub_manifest_pkg_info(self, post_event):
        self._set_permissions("monolith.add_submanifestpkginfo")
        manifest = force_manifest()
        sub_manifest = force_sub_manifest(manifest=manifest)
        self.assertEqual(manifest.version, 1)
        pkg_info_name = force_name()
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self._post_json_data(reverse("monolith_api:sub_manifest_pkg_infos"), data={
                'sub_manifest': sub_manifest.pk,
                'pkg_info_name': pkg_info_name.name,
                'featured_item': True,
                'key': 'default_installs',
                'excluded_tags': [],
                'tag_shards': []
            })
        self.assertEqual(response.status_code, 201)
        sub_manifest_pkg_info = SubManifestPkgInfo.objects.get(sub_manifest=sub_manifest,
                                                               pkg_info_name=pkg_info_name)
        self.assertEqual(response.json(), {
            'id': sub_manifest_pkg_info.pk,
            'sub_manifest': sub_manifest_pkg_info.sub_manifest.pk,
            'key': 'default_installs',
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
        self.assertEqual(sub_manifest_pkg_info.key, "default_installs")
        self.assertTrue(sub_manifest_pkg_info.featured_item)
        self.assertEqual(sub_manifest_pkg_info.options,
                         {"shards": {"modulo": 100, "default": 100}})
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 2)
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload, 
            {"action": "created",
             "object": {
                 "model": "monolith.submanifestpkginfo",
                 "pk": str(sub_manifest_pkg_info.pk),
                 "new_value": {
                    "pk": sub_manifest_pkg_info.pk,
                    "key": 'default_installs',
                    "sub_manifest": sub_manifest.serialize_for_event(keys_only=True),
                    "pkg_info_name": pkg_info_name.serialize_for_event(),
                    "featured_item": True,
                    "options": {'shards': {'default': 100, 'modulo': 100}},
                    "created_at": sub_manifest_pkg_info.created_at,
                    "updated_at": sub_manifest_pkg_info.updated_at
                 }
             }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"monolith_sub_manifest_pkg_info": [str(sub_manifest_pkg_info.pk)],
                                               "monolith_sub_manifest": [str(sub_manifest.pk)],
                                               "monolith_pkg_info_name": [str(pkg_info_name.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])

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

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_sub_manifest_pkg_info(self, post_event):
        sub_manifest_pkg_info = force_sub_manifest_pkg_info()
        prev_value = sub_manifest_pkg_info.serialize_for_event()
        self._set_permissions("monolith.change_submanifestpkginfo")
        new_manifest = force_manifest()
        new_sub_manifest = force_sub_manifest(manifest=new_manifest)
        self.assertEqual(new_manifest.version, 1)
        new_pkg_info_name = force_name()
        new_condition = force_condition()
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self._put_json_data(
                reverse("monolith_api:sub_manifest_pkg_info", args=(sub_manifest_pkg_info.pk,)),
                data={
                    'sub_manifest': new_sub_manifest.pk,
                    'pkg_info_name': new_pkg_info_name.name,
                    'key': 'managed_updates',
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
            'key': 'managed_updates',
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
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload, {
                "action": "updated",
                "object": {
                    "model": "monolith.submanifestpkginfo",
                    "pk": str(test_sub_manifest_pkg_info.pk),
                    "prev_value": prev_value,
                    "new_value": {
                        "condition": new_condition.serialize_for_event(keys_only=True),
                        "pk": test_sub_manifest_pkg_info.pk,
                        "key": 'managed_updates',
                        "sub_manifest": new_sub_manifest.serialize_for_event(keys_only=True),
                        "pkg_info_name": new_pkg_info_name.serialize_for_event(),
                        "featured_item": False,
                        "options": {'excluded_tags': [str(excluded_tag.name)], 'shards': {'default': 0,
                                                                                          'modulo': 42,
                                                                                          'tags':
                                                                                          {str(shard_tag.name): 17}}},
                        "created_at": test_sub_manifest_pkg_info.created_at,
                        "updated_at": test_sub_manifest_pkg_info.updated_at
                    }
                }
            }
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"monolith_sub_manifest_pkg_info": [str(test_sub_manifest_pkg_info.pk)],
                                               "monolith_sub_manifest": [str(new_sub_manifest.pk)],
                                               "monolith_pkg_info_name": [str(new_pkg_info_name.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])

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

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_sub_manifest_pkg_info(self, post_event):
        sub_manifest_pkg_info = force_sub_manifest_pkg_info()
        prev_value = sub_manifest_pkg_info.serialize_for_event()
        sub_manifest = sub_manifest_pkg_info.sub_manifest
        manifest = sub_manifest.manifestsubmanifest_set.first().manifest
        self.assertEqual(manifest.version, 1)
        force_pkg_info(sub_manifest=sub_manifest)
        self._set_permissions("monolith.delete_submanifestpkginfo")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("monolith_api:sub_manifest_pkg_info", args=(sub_manifest_pkg_info.pk,)))
        self.assertEqual(response.status_code, 204)
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 2)
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload, {
                "action": "deleted",
                "object": {
                    "model": "monolith.submanifestpkginfo",
                    "pk": str(prev_value['pk']),
                    "prev_value": prev_value
                }
            }
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], 
                         {"monolith_sub_manifest_pkg_info": [str(sub_manifest_pkg_info.pk)],
                          "monolith_sub_manifest": [str(sub_manifest.pk)],
                          "monolith_pkg_info_name": [str(sub_manifest_pkg_info.pkg_info_name.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])

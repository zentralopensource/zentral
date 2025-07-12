import copy
from datetime import datetime
from functools import reduce
import hashlib
from io import BytesIO
import operator
from unittest.mock import patch
import uuid
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.test import TestCase, override_settings
from django.utils.crypto import get_random_string
from django.utils.text import slugify
from accounts.models import User
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit, Tag
from zentral.contrib.monolith.events import MonolithSyncCatalogsRequestEvent
from zentral.contrib.monolith.models import (Catalog, Condition, Enrollment, EnrolledMachine,
                                             PkgInfo, PkgInfoName)
from zentral.contrib.monolith.repository_backends import load_repository_backend
from zentral.contrib.monolith.repository_backends.azure import AzureRepository
from zentral.contrib.monolith.repository_backends.s3 import S3Repository
from zentral.contrib.monolith.repository_backends.virtual import VirtualRepository
from zentral.contrib.munki.models import ManagedInstall
from zentral.core.events.base import AuditEvent
from zentral.core.stores.conf import stores
from zentral.utils.provisioning import provision
from utils.packages import build_dummy_package
from .utils import (CLOUDFRONT_PRIVKEY_PEM,
                    force_catalog, force_category, force_condition,
                    force_manifest, force_name,
                    force_pkg_info,
                    force_sub_manifest, force_sub_manifest_pkg_info,
                    force_repository)


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MonolithSetupViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        # provision the stores
        provision()
        stores._load(force=True)
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group] + stores.admin_console_store.events_url_authorized_roles)
        # mbu
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
        cls.mbu.create_enrollment_business_unit()
        # repository
        cls.repository = force_repository()
        # manifest
        cls.manifest = force_manifest(mbu=cls.mbu)
        # catalog
        cls.catalog_1 = force_catalog(repository=cls.repository, manifest=cls.manifest)
        # pkginfo name
        cls.pkginfo_name_1 = PkgInfoName.objects.create(name="aaaa first name")
        # pkginfo
        cls.pkginfo_1_1 = PkgInfo.objects.create(repository=cls.repository,
                                                 name=cls.pkginfo_name_1, version="1.0",
                                                 data={"name": cls.pkginfo_name_1.name,
                                                       "version": "1.0"})
        cls.pkginfo_1_1.catalogs.set([cls.catalog_1])
        # enrollment
        cls.enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=cls.mbu)
        cls.enrollment = Enrollment.objects.create(secret=cls.enrollment_secret, manifest=cls.manifest)
        # enrolled machine
        cls.serial_number = get_random_string(12)
        cls.enrolled_machine = EnrolledMachine.objects.create(enrollment=cls.enrollment,
                                                              serial_number=cls.serial_number)
        # simulate 1 install of 1v1
        ManagedInstall.objects.create(
            machine_serial_number=cls.serial_number,
            name=cls.pkginfo_name_1.name,
            installed_version=cls.pkginfo_1_1.version,
            installed_at=datetime.utcnow()
        )

    # utility methods

    def _login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def _login(self, *permissions):
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
        self.client.force_login(self.user)

    # index

    def test_index_redirect(self):
        self._login_redirect(reverse("monolith:index"))

    def test_index_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:index"))
        self.assertEqual(response.status_code, 403)

    def test_index(self):
        self._login("monolith.view_manifest")
        response = self.client.get(reverse("monolith:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/index.html")

    # repositories

    def test_repositories_redirect(self):
        self._login_redirect(reverse("monolith:repositories"))

    def test_repositories_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:repositories"))
        self.assertEqual(response.status_code, 403)

    def test_repositories_all_links(self):
        repository = force_repository()
        repository2 = force_repository(provisioning_uid=get_random_string(12))
        self._login("monolith.view_repository", "monolith.change_repository", "monolith.delete_repository")
        response = self.client.get(reverse("monolith:repositories"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/repository_list.html")
        self.assertContains(response, repository.get_absolute_url())
        self.assertContains(response, repository.name)
        self.assertContains(response, repository2.name)
        self.assertContains(response, reverse("monolith:update_repository", args=(repository.pk,)))
        self.assertNotContains(response, reverse("monolith:update_repository", args=(repository2.pk,)))
        self.assertContains(response, reverse("monolith:delete_repository", args=(repository.pk,)))
        self.assertNotContains(response, reverse("monolith:delete_repository", args=(repository2.pk,)))

    def test_repositories_no_links(self):
        repository = force_repository()
        repository2 = force_repository(provisioning_uid=get_random_string(12))
        self._login("monolith.view_repository")
        response = self.client.get(reverse("monolith:repositories"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/repository_list.html")
        self.assertContains(response, repository.get_absolute_url())
        self.assertContains(response, repository.name)
        self.assertContains(response, repository2.name)
        self.assertNotContains(response, reverse("monolith:update_repository", args=(repository.pk,)))
        self.assertNotContains(response, reverse("monolith:update_repository", args=(repository2.pk,)))
        self.assertNotContains(response, reverse("monolith:delete_repository", args=(repository.pk,)))
        self.assertNotContains(response, reverse("monolith:delete_repository", args=(repository2.pk,)))

    # create repository

    def test_create_repository_redirect(self):
        self._login_redirect(reverse("monolith:create_repository"))

    def test_create_repository_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:create_repository"))
        self.assertEqual(response.status_code, 403)

    def test_create_repository_get(self):
        self._login("monolith.add_repository")
        response = self.client.get(reverse("monolith:create_repository"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/repository_form.html")

    def test_create_s3_repository_invalid_private_key(self):
        self._login("monolith.add_repository", "monolith.view_repository")
        name = get_random_string(12)
        bucket = get_random_string(12)
        response = self.client.post(reverse("monolith:create_repository"),
                                    {"r-name": name,
                                     "r-backend": "S3",
                                     "s3-bucket": bucket,
                                     "s3-cloudfront_domain": "yada.cloudfront.net",
                                     "s3-cloudfront_key_id": "YADA",
                                     "s3-cloudfront_privkey_pem": "YADA"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/repository_form.html")
        self.assertFormError(
            response.context["s3_form"], "cloudfront_privkey_pem",
            "Invalid private key."
        )

    def test_create_s3_repository_missing_cf_domain_key_id(self):
        self._login("monolith.add_repository", "monolith.view_repository")
        name = get_random_string(12)
        bucket = get_random_string(12)
        response = self.client.post(reverse("monolith:create_repository"),
                                    {"r-name": name,
                                     "r-backend": "S3",
                                     "s3-bucket": bucket,
                                     "s3-cloudfront_privkey_pem": CLOUDFRONT_PRIVKEY_PEM},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/repository_form.html")
        self.assertFormError(
            response.context["s3_form"], "cloudfront_domain",
            "This field is required when configuring Cloudfront."
        )
        self.assertFormError(
            response.context["s3_form"], "cloudfront_key_id",
            "This field is required when configuring Cloudfront."
        )

    def test_create_s3_repository_missing_cf_privkey(self):
        self._login("monolith.add_repository", "monolith.view_repository")
        name = get_random_string(12)
        bucket = get_random_string(12)
        response = self.client.post(reverse("monolith:create_repository"),
                                    {"r-name": name,
                                     "r-backend": "S3",
                                     "s3-bucket": bucket,
                                     "s3-cloudfront_domain": "yada.cloudfront.net",
                                     "s3-cloudfront_key_id": "YADA"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/repository_form.html")
        self.assertFormError(
            response.context["s3_form"], "cloudfront_privkey_pem",
            "This field is required when configuring Cloudfront."
        )

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_azure_repository(self, post_event, send_notification):
        self._login("monolith.add_repository", "monolith.view_repository")
        name = get_random_string(12)
        storage_account = get_random_string(12)
        container = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("monolith:create_repository"),
                                        {"r-name": name,
                                         "r-backend": "AZURE",
                                         "azure-storage_account": storage_account,
                                         "azure-container": container},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/repository_detail.html")
        self.assertContains(response, name)
        repository = response.context["object"]
        self.assertEqual(repository.name, name)
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
        self.assertIsInstance(repository_backend, AzureRepository)
        self.assertEqual(repository_backend._credential_kwargs, {})

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_s3_repository(self, post_event, send_notification):
        self._login("monolith.add_repository", "monolith.view_repository")
        name = get_random_string(12)
        bucket = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("monolith:create_repository"),
                                        {"r-name": name,
                                         "r-backend": "S3",
                                         "s3-bucket": bucket},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/repository_detail.html")
        self.assertContains(response, name)
        repository = response.context["object"]
        self.assertEqual(repository.name, name)
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
        self.assertIsInstance(repository_backend, S3Repository)
        self.assertEqual(repository_backend.signature_version, "s3v4")

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_virtual_repository(self, post_event, send_notification):
        self._login("monolith.add_repository", "monolith.view_repository")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("monolith:create_repository"),
                                        {"r-name": name,
                                         "r-backend": "VIRTUAL"},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/repository_detail.html")
        self.assertContains(response, name)
        repository = response.context["object"]
        self.assertEqual(repository.name, name)
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
        repository_backend = load_repository_backend(repository)
        self.assertIsInstance(repository_backend, VirtualRepository)

    # repository

    def test_repository_redirect(self):
        repository = force_repository()
        self._login_redirect(reverse("monolith:repository", args=(repository.pk,)))

    def test_repository_permission_denied(self):
        repository = force_repository()
        self._login()
        response = self.client.get(reverse("monolith:repository", args=(repository.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_repository_get_all_links(self):
        repository = force_repository()
        self._login(
            "monolith.view_repository",
            "monolith.change_repository",
            "monolith.delete_repository",
            "monolith.sync_repository"
        )
        response = self.client.get(reverse("monolith:repository", args=(repository.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/repository_detail.html")
        self.assertContains(response, repository.name)
        self.assertContains(response, repository.get_backend_kwargs()["secret_access_key"])
        self.assertContains(response, reverse("monolith:update_repository", args=(repository.pk,)))
        self.assertContains(response, reverse("monolith:delete_repository", args=(repository.pk,)))
        self.assertContains(response, reverse("monolith:sync_repository", args=(repository.pk,)))

    def test_provisioned_repository_get_sync_only_no_secrets(self):
        repository = force_repository(provisioning_uid=get_random_string(12))
        self._login(
            "monolith.view_repository",
            "monolith.change_repository",
            "monolith.delete_repository",
            "monolith.sync_repository"
        )
        response = self.client.get(reverse("monolith:repository", args=(repository.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/repository_detail.html")
        self.assertContains(response, repository.name)
        self.assertNotContains(response, repository.get_backend_kwargs()["secret_access_key"])
        self.assertNotContains(response, reverse("monolith:update_repository", args=(repository.pk,)))
        self.assertNotContains(response, reverse("monolith:delete_repository", args=(repository.pk,)))
        self.assertContains(response, reverse("monolith:sync_repository", args=(repository.pk,)))

    def test_repository_get_no_links(self):
        repository = force_repository()
        self._login("monolith.view_repository")
        response = self.client.get(reverse("monolith:repository", args=(repository.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/repository_detail.html")
        self.assertContains(response, repository.name)
        self.assertNotContains(response, reverse("monolith:update_repository", args=(repository.pk,)))
        self.assertNotContains(response, reverse("monolith:delete_repository", args=(repository.pk,)))
        self.assertNotContains(response, reverse("monolith:sync_repository", args=(repository.pk,)))

    def test_repository_get_update_only(self):
        repository = force_repository()
        self._login("monolith.view_repository", "monolith.change_repository")
        response = self.client.get(reverse("monolith:repository", args=(repository.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/repository_detail.html")
        self.assertContains(response, repository.name)
        self.assertContains(response, reverse("monolith:update_repository", args=(repository.pk,)))
        self.assertNotContains(response, reverse("monolith:delete_repository", args=(repository.pk,)))
        self.assertNotContains(response, reverse("monolith:sync_repository", args=(repository.pk,)))

    def test_repository_get_delete_only(self):
        repository = force_repository()
        self._login("monolith.view_repository", "monolith.delete_repository")
        response = self.client.get(reverse("monolith:repository", args=(repository.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/repository_detail.html")
        self.assertContains(response, repository.name)
        self.assertNotContains(response, reverse("monolith:update_repository", args=(repository.pk,)))
        self.assertContains(response, reverse("monolith:delete_repository", args=(repository.pk,)))
        self.assertNotContains(response, reverse("monolith:sync_repository", args=(repository.pk,)))

    # update repository

    def test_update_repository_redirect(self):
        repository = force_repository()
        self._login_redirect(reverse("monolith:update_repository", args=(repository.pk,)))

    def test_update_repository_permission_denied(self):
        repository = force_repository()
        self._login()
        response = self.client.get(reverse("monolith:update_repository", args=(repository.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_repository_get(self):
        repository = force_repository()
        self._login("monolith.change_repository")
        response = self.client.get(reverse("monolith:update_repository", args=(repository.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/repository_form.html")

    def test_update_provisioned_repository_get_404(self):
        repository = force_repository(provisioning_uid=get_random_string(12))
        self._login("monolith.change_repository")
        response = self.client.get(reverse("monolith:update_repository", args=(repository.pk,)))
        self.assertEqual(response.status_code, 404)

    def test_update_s3_repository_bad_mbu(self):
        repository = force_repository()
        manifest = force_manifest()
        self.assertIsNone(repository.meta_business_unit)
        self.assertNotEqual(manifest.meta_business_unit, self.mbu)
        force_catalog(repository=repository, manifest=manifest)
        self._login("monolith.change_repository")
        response = self.client.post(reverse("monolith:update_repository", args=(repository.pk,)),
                                    {"r-name": get_random_string(12),
                                     "r-meta_business_unit": self.mbu.pk,
                                     "r-backend": "S3",
                                     "s3-bucket": get_random_string(12)})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/repository_form.html")
        self.assertFormError(
            response.context["form"], "meta_business_unit",
            f"Repository linked to manifest '{manifest}' which has a different business unit."
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
        new_name = get_random_string(12)
        new_bucket = get_random_string(12)
        self._login("monolith.change_repository", "monolith.view_repository")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("monolith:update_repository", args=(repository.pk,)),
                                        {"r-name": new_name,
                                         "r-meta_business_unit": self.mbu.pk,
                                         "r-backend": "S3",
                                         "s3-bucket": new_bucket,
                                         "s3-region_name": "us-east2",
                                         "s3-prefix": "prefix",
                                         "s3-access_key_id": "11111111111111111111",
                                         "s3-secret_access_key": "22222222222222222222",
                                         "s3-assume_role_arn": "arn:aws:iam::123456789012:role/S3Access",
                                         "s3-signature_version": "s3v2",
                                         "s3-endpoint_url": "https://endpoint.example.com",
                                         "s3-cloudfront_domain": "yada.cloudfront.net",
                                         "s3-cloudfront_key_id": "YADA",
                                         "s3-cloudfront_privkey_pem": CLOUDFRONT_PRIVKEY_PEM},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/repository_detail.html")
        self.assertContains(response, new_name)
        repository = response.context["object"]
        self.assertEqual(repository.name, new_name)
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

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_azure_repository(self, post_event, send_notification):
        repository = force_repository()
        manifest = force_manifest(mbu=self.mbu)
        self.assertEqual(manifest.version, 1)
        # two catalogs, only one manifest version bump!
        force_catalog(repository=repository, manifest=manifest)
        force_catalog(repository=repository, manifest=manifest)
        prev_value = repository.serialize_for_event()
        new_name = get_random_string(12)
        storage_account = get_random_string(12)
        container = get_random_string(12)
        tenant_id = str(uuid.uuid4())
        client_id = str(uuid.uuid4())
        client_secret = get_random_string(12)
        self._login("monolith.change_repository", "monolith.view_repository")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("monolith:update_repository", args=(repository.pk,)),
                                        {"r-name": new_name,
                                         "r-meta_business_unit": self.mbu.pk,
                                         "r-backend": "AZURE",
                                         "azure-storage_account": storage_account,
                                         "azure-container": container,
                                         "azure-prefix": "prefix",
                                         "azure-tenant_id": tenant_id,
                                         "azure-client_id": client_id,
                                         "azure-client_secret": client_secret},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/repository_detail.html")
        self.assertContains(response, new_name)
        repository = response.context["object"]
        self.assertEqual(repository.name, new_name)
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
                     "backend": "AZURE",
                     "backend_kwargs": {
                         "storage_account": storage_account,
                         "container": container,
                         "prefix": "prefix",
                         "tenant_id": tenant_id,
                         "client_id": client_id,
                         "client_secret_hash": hashlib.sha256(client_secret.encode("utf-8")).hexdigest(),
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
        self.assertEqual(repository_backend.storage_account, storage_account)
        self.assertEqual(repository_backend.container, container)
        self.assertEqual(repository_backend.prefix, "prefix")
        self.assertEqual(repository_backend._credential_kwargs,
                         {"client_id": client_id,
                          "tenant_id": tenant_id,
                          "client_secret": client_secret})
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 2)  # only one bump

    # delete repository

    def test_delete_repository_redirect(self):
        repository = force_repository()
        self._login_redirect(reverse("monolith:delete_repository", args=(repository.pk,)))

    def test_delete_repository_permission_denied(self):
        repository = force_repository()
        self._login()
        response = self.client.get(reverse("monolith:delete_repository", args=(repository.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_linked_repository_get_not_found(self):
        repository = force_repository()
        manifest = force_manifest()
        force_catalog(repository=repository, manifest=manifest)
        self._login("monolith.delete_repository")
        response = self.client.get(reverse("monolith:delete_repository", args=(repository.pk,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_provisioned_repository_get_not_found(self):
        repository = force_repository(provisioning_uid=get_random_string(12))
        self._login("monolith.delete_repository")
        response = self.client.get(reverse("monolith:delete_repository", args=(repository.pk,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_repository_get(self):
        repository = force_repository()
        self._login("monolith.delete_repository")
        response = self.client.get(reverse("monolith:delete_repository", args=(repository.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/repository_confirm_delete.html")

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_repository(self, post_event, send_notification):
        repository = force_repository()
        prev_value = repository.serialize_for_event()
        self._login("monolith.delete_repository", "monolith.view_repository")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("monolith:delete_repository", args=(repository.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/repository_list.html")
        self.assertNotContains(response, repository.name)
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

    def test_sync_repository_redirect(self):
        repository = force_repository()
        self._login_redirect(reverse("monolith:sync_repository", args=(repository.pk,)))

    def test_sync_repository_permission_denied(self):
        repository = force_repository()
        self._login("monolith.change_repository")
        response = self.client.get(reverse("monolith:sync_repository", args=(repository.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("zentral.contrib.monolith.views.load_repository_backend")
    def test_sync_repository(self, load_repository_backend, post_event, send_notification):
        repository = force_repository()
        self._login("monolith.sync_repository", "monolith.view_repository")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("monolith:sync_repository", args=(repository.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/repository_detail.html")
        self.assertContains(response, repository.name)
        self.assertContains(response, "Repository synced")
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MonolithSyncCatalogsRequestEvent)
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"monolith_repository": [str(repository.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])
        send_notification.assert_called_once_with("monolith.repository", str(repository.pk))

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("zentral.contrib.monolith.views.load_repository_backend")
    def test_sync_repository_error(self, load_repository_backend, post_event, send_notification):
        load_repository_backend.return_value.sync_catalogs.side_effect = ValueError("YoLoFoMo")
        repository = force_repository()
        self._login("monolith.sync_repository", "monolith.view_repository")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("monolith:sync_repository", args=(repository.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 0)
        self.assertTemplateUsed(response, "monolith/repository_detail.html")
        self.assertContains(response, repository.name)
        self.assertNotContains(response, "Repository synced")
        self.assertContains(response, "Could not sync repository: YoLoFoMo")
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MonolithSyncCatalogsRequestEvent)
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"monolith_repository": [str(repository.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])
        send_notification.assert_not_called()

    # pkg infos

    def test_pkg_infos_login_redirect(self):
        self._login_redirect(reverse("monolith:pkg_infos"))

    def test_pkg_infos_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:pkg_infos"))
        self.assertEqual(response.status_code, 403)

    def test_pkg_infos(self):
        self._login("monolith.view_pkginfo")
        response = self.client.get(reverse("monolith:pkg_infos"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/pkginfo_list.html")
        self.assertContains(response, self.pkginfo_name_1.name)

    def test_pkg_infos_search(self):
        self._login("monolith.view_pkginfo")
        response = self.client.get(reverse("monolith:pkg_infos"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/pkginfo_list.html")
        self.assertContains(response, self.pkginfo_name_1.name)
        response = self.client.get(reverse("monolith:pkg_infos"), {"name": "does not exists"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/pkginfo_list.html")
        self.assertContains(response, "We didn't find any item related to your search")
        self.assertContains(response, reverse("monolith:pkg_infos") + '">all the items')

    # pkg info name

    def test_pkg_info_name_login_redirect(self):
        self._login_redirect(reverse("monolith:pkg_info_name", args=(self.pkginfo_name_1.pk,)))

    def test_pkg_info_name_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:pkg_info_name", args=(self.pkginfo_name_1.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_pkg_info_name(self):
        self._login("monolith.view_pkginfoname", "monolith.view_pkginfo")
        response = self.client.get(reverse("monolith:pkg_info_name", args=(self.pkginfo_name_1.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/pkg_info_name.html")
        self.assertContains(response, self.pkginfo_name_1.name)

    def test_pkg_info_name_events_login_redirect(self):
        self._login_redirect(reverse("monolith:pkg_info_name_events", args=(self.pkginfo_name_1.pk,)))

    def test_pkg_info_name_fetch_events_login_redirect(self):
        self._login_redirect(reverse("monolith:fetch_pkg_info_name_events", args=(self.pkginfo_name_1.pk,)))

    def test_pkg_info_name_events_store_redirect_login_redirect(self):
        self._login_redirect(reverse("monolith:pkg_info_name_events_store_redirect", args=(self.pkginfo_name_1.pk,)))

    def test_pkg_info_name_events_permission_denied(self):
        self._login("monolith.view_pkginfo")
        response = self.client.get(reverse("monolith:pkg_info_name_events",
                                   args=(self.pkginfo_name_1.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_pkg_info_name_fetch_events_permission_denied(self):
        self._login("monolith.view_pkginfo")
        response = self.client.get(reverse("monolith:fetch_pkg_info_name_events",
                                   args=(self.pkginfo_name_1.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_pkg_info_name_events_store_redirect_permission_denied(self):
        self._login("monolith.view_pkginfo")
        response = self.client.get(reverse("monolith:pkg_info_name_events_store_redirect",
                                   args=(self.pkginfo_name_1.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.ElasticsearchStore.get_aggregated_object_event_counts")
    def test_pkg_info_name_events(self, get_aggregated_object_event_counts):
        get_aggregated_object_event_counts.return_value = {}
        self._login("monolith.view_pkginfo", "monolith.view_pkginfoname")
        response = self.client.get(reverse("monolith:pkg_info_name_events",
                                   args=(self.pkginfo_name_1.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/pkg_info_name_events.html")

    @patch("zentral.core.stores.backends.elasticsearch.ElasticsearchStore.fetch_object_events")
    def test_pkg_info_name_fetch_events(self, fetch_object_events):
        fetch_object_events.return_value = ([], None)
        self._login("monolith.view_pkginfo", "monolith.view_pkginfoname")
        response = self.client.get(reverse("monolith:fetch_pkg_info_name_events",
                                   args=(self.pkginfo_name_1.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/stores/events_events.html")

    def test_pkg_info_name_events_store_redirect(self):
        self._login("monolith.view_pkginfo", "monolith.view_pkginfoname")
        response = self.client.get(reverse("monolith:pkg_info_name_events_store_redirect",
                                   args=(self.pkginfo_name_1.pk,)))
        # dev store cannot redirect
        self.assertRedirects(response, reverse("monolith:pkg_info_name_events", args=(self.pkginfo_name_1.pk,)))

    # create pkg info name

    def test_create_pkg_info_name_login_redirect(self):
        self._login_redirect(reverse("monolith:create_pkg_info_name"))

    def test_create_pkg_info_name_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:create_pkg_info_name"))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_pkg_info_name(self, post_event):
        self._login("monolith.add_pkginfoname", "monolith.view_pkginfoname")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("monolith:create_pkg_info_name"), {"name": name}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/pkg_info_name.html")
        self.assertContains(response, name)
        pkg_info_name = response.context["object"]
        self.assertEqual(pkg_info_name.name, name)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "monolith.pkginfoname",
                 "pk": str(pkg_info_name.pk),
                 "new_value": {
                     "pk": pkg_info_name.pk,
                     "name": name,
                     "created_at": pkg_info_name.created_at,
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"munki_pkginfo_name": [name]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])

    # delete pkg info name

    def test_delete_pkg_info_name_login_redirect(self):
        self._login_redirect(reverse("monolith:delete_pkg_info_name", args=(self.pkginfo_name_1.pk,)))

    def test_delete_pkg_info_name_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:delete_pkg_info_name", args=(self.pkginfo_name_1.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_pkg_info_name_404(self):
        self._login("monolith.delete_pkginfoname")
        response = self.client.post(reverse("monolith:delete_pkg_info_name", args=(self.pkginfo_name_1.pk,)))
        self.assertEqual(response.status_code, 404)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_pkg_info_name(self, post_event):
        self._login("monolith.delete_pkginfoname", "monolith.view_pkginfo")
        pkg_info_name = force_name()
        prev_pk = pkg_info_name.pk
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("monolith:delete_pkg_info_name", args=(pkg_info_name.pk,)),
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/pkginfo_list.html")
        self.assertNotContains(response, pkg_info_name.name)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "monolith.pkginfoname",
                 "pk": str(prev_pk),
                 "prev_value": {
                     "pk": prev_pk,
                     "name": pkg_info_name.name,
                     "created_at": pkg_info_name.created_at,
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"munki_pkginfo_name": [pkg_info_name.name]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])

    # upload package

    def test_upload_package_login_redirect(self):
        self._login_redirect(reverse("monolith:upload_package"))

    def test_upload_package_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:upload_package"))
        self.assertEqual(response.status_code, 403)

    def test_upload_package_get_no_name(self):
        self._login("monolith.add_pkginfo")
        pkg_info_name = force_name()
        response = self.client.get(reverse("monolith:upload_package"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/package_form.html")
        self.assertContains(response, "Upload package")
        choices = list(response.context["form"].fields["name"].queryset.all())
        self.assertEqual(set(choices), {pkg_info_name, self.pkginfo_name_1})

    def test_upload_package_get_name(self):
        self._login("monolith.add_pkginfo")
        pkg_info_name = force_name()
        response = self.client.get(reverse("monolith:upload_package"), {"pin_id": pkg_info_name.pk})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/package_form.html")
        self.assertContains(response, "Upload package")
        self.assertNotIn("name", response.context["form"].fields)

    def test_upload_package_catalog_different_repository(self):
        self._login("monolith.add_pkginfo")
        pkg_info_name = force_name()
        file = BytesIO(build_dummy_package())
        file.name = "test123.pkg"
        catalog = force_catalog(repository=force_repository(virtual=True))
        catalog2 = force_catalog(repository=force_repository(virtual=True))
        response = self.client.post(
            reverse("monolith:upload_package"),
            {"file": file,
             "name": pkg_info_name.pk,
             "catalogs": [catalog.pk, catalog2.pk]},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/package_form.html")
        self.assertFormError(
            response.context["form"], "catalogs",
            "The catalogs must be from the same repository."
        )

    def test_upload_package_catalog_category_different_repository(self):
        self._login("monolith.add_pkginfo")
        pkg_info_name = force_name()
        file = BytesIO(build_dummy_package())
        file.name = "test123.pkg"
        catalog = force_catalog(repository=force_repository(virtual=True))
        category = force_category(repository=force_repository(virtual=True))
        response = self.client.post(
            reverse("monolith:upload_package"),
            {"file": file,
             "name": pkg_info_name.pk,
             "category": category.pk,
             "catalogs": [catalog.pk]},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/package_form.html")
        self.assertFormError(
            response.context["form"], "category",
            "The category must be from the same repository as the catalogs."
        )

    def test_upload_package_catalog_category_wrong_choices(self):
        self._login("monolith.add_pkginfo")
        pkg_info_name = force_name()
        file = BytesIO(build_dummy_package())
        file.name = "test123.pkg"
        repository = force_repository(virtual=False)
        catalog = force_catalog(repository=repository)
        category = force_category(repository=repository)
        response = self.client.post(
            reverse("monolith:upload_package"),
            {"file": file,
             "name": pkg_info_name.pk,
             "category": category.pk,
             "catalogs": [catalog.pk]},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/package_form.html")
        self.assertFormError(
            response.context["form"], "catalogs",
            f"Select a valid choice. {catalog.pk} is not one of the available choices."
        )
        self.assertFormError(
            response.context["form"], "category",
            "Select a valid choice. That choice is not one of the available choices."
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_upload_package(self, post_event):
        self._login("monolith.add_pkginfo", "monolith.view_pkginfoname", "monolith.view_pkginfo")
        pkg_info_name = force_name()
        file = BytesIO(build_dummy_package())
        file.name = "test123.pkg"
        repository = force_repository(virtual=True)
        catalog = force_catalog(repository=repository)
        category = force_category(repository=repository)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("monolith:upload_package"),
                {"file": file,
                 "name": pkg_info_name.pk,
                 "category": category.pk,
                 "catalogs": [catalog.pk]},
                follow=True
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/pkg_info_name.html")
        pkg_info = pkg_info_name.pkginfo_set.first()
        self.assertTrue(pkg_info.local is True)
        self.assertEqual(pkg_info.file.name, f"monolith/packages/{pkg_info.pk:08d}.pkg")
        self.assertEqual(pkg_info.data["installer_item_location"], file.name)
        self.assertEqual(pkg_info.data["name"], pkg_info_name.name)
        self.assertEqual(
            pkg_info.data["receipts"],
            [{'installed_size': 12,
              'packageid': 'io.zentral.test123',
              'version': '1.0'}]
        )
        self.assertEqual(pkg_info.data["version"], "1.0")
        self.assertEqual(pkg_info.version, "1.0")
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        event_payload_data = event.payload["object"]["new_value"].pop("data")
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "monolith.pkginfo",
                 "pk": str(pkg_info.pk),
                 "new_value": {
                     "pk": pkg_info.pk,
                     "local": True,
                     "name": pkg_info_name.name,
                     "category": {"pk": category.pk, "name": category.name,
                                  "repository": {"pk": repository.pk, "name": repository.name}},
                     "catalogs":  [{"pk": catalog.pk, "name": catalog.name,
                                    "repository": {"pk": repository.pk, "name": repository.name}}],
                     "requires": [],
                     "update_for": [],
                     "version": "1.0",
                     "created_at": pkg_info.created_at,
                     "updated_at": pkg_info.updated_at,
                 }
              }}
        )
        self.assertEqual(event_payload_data["name"], pkg_info_name.name)
        metadata = event.metadata.serialize()
        self.assertEqual(
            metadata["objects"],
            {"munki_pkginfo": [f"{pkg_info_name.name}|1.0"],
             "munki_pkginfo_name": [pkg_info_name.name]}
        )
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])
        pkg_info.file.delete()

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_upload_package_from_pkg_info_name(self, post_event):
        self._login("monolith.add_pkginfo", "monolith.view_pkginfoname", "monolith.view_pkginfo")
        repository = force_repository(virtual=True)
        catalog = force_catalog(repository=repository)
        pkg_info_category = force_category(repository=repository)
        pkg_info_name = force_name()
        pkg_info_name_required = force_name()
        pkg_info_name_update_for = force_name()
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        file = BytesIO(build_dummy_package())
        file.name = "test123.pkg"
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                "{}?pin_id={}".format(reverse("monolith:upload_package"), pkg_info_name.pk),
                {"file": file,
                 "display_name": "Yolo",
                 "description": "Fomo",
                 "catalogs": [catalog.pk],
                 "category": pkg_info_category.pk,
                 "requires": [pkg_info_name_required.pk],
                 "update_for": [pkg_info_name_update_for.pk],
                 "excluded_tags": [excluded_tag.pk],
                 "shard_modulo": 5,
                 "default_shard": 2,
                 f"tag-shard-{shard_tag.pk}": 5},
                follow=True
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/pkg_info_name.html")
        pkg_info = pkg_info_name.pkginfo_set.first()
        self.assertTrue(pkg_info.local is True)
        self.assertEqual(pkg_info.file.name, f"monolith/packages/{pkg_info.pk:08d}.pkg")
        data = {
            'name': pkg_info_name.name,
            'version': '1.0',
            'category': pkg_info_category.name,
            'receipts': [{'version': '1.0',
                          'packageid': 'io.zentral.test123',
                          'installed_size': 12}],
            'requires': [pkg_info_name_required.name],
            'autoremove': False,
            'update_for': [pkg_info_name_update_for.name],
            'description': 'Fomo',
            'display_name': 'Yolo',
            'uninstallable': True,
            'installed_size': 12,
            'uninstall_method': 'removepackages',
            'zentral_monolith': {
                'shards': {
                    'tags': {
                        shard_tag.name: 5
                    },
                    'modulo': 5,
                    'default': 2
                 },
                'excluded_tags': [excluded_tag.name]
            },
            'minimum_os_version': '10.11.0',
            'unattended_install': True,
            'installer_item_size': 2,
            'installer_item_hash': pkg_info.data["installer_item_hash"],
            'unattended_uninstall': True,
            'installer_item_location': 'test123.pkg'
        }
        self.assertEqual(pkg_info.data, data)
        self.assertEqual(pkg_info.version, "1.0")
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "monolith.pkginfo",
                 "pk": str(pkg_info.pk),
                 "new_value": {
                     "pk": pkg_info.pk,
                     "local": True,
                     "name": pkg_info_name.name,
                     "category": {"name": pkg_info_category.name, "pk": pkg_info_category.pk,
                                  "repository": {"pk": repository.pk,
                                                 "name": repository.name}},
                     "catalogs":  [{"pk": catalog.pk, "name": catalog.name,
                                    "repository": {"pk": repository.pk,
                                                   "name": repository.name}}],
                     "data": data,
                     "requires": [pkg_info_name_required.name],
                     "update_for": [pkg_info_name_update_for.name],
                     "version": "1.0",
                     "created_at": pkg_info.created_at,
                     "updated_at": pkg_info.updated_at,
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(
            metadata["objects"],
            {"munki_pkginfo": [f"{pkg_info_name.name}|1.0"],
             "munki_pkginfo_name": [pkg_info_name.name]}
        )
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])
        pkg_info.file.delete()

    def test_upload_package_conflict(self):
        self._login("monolith.add_pkginfo")
        pkg_info = force_pkg_info()
        file = BytesIO(build_dummy_package(name=pkg_info.name.name, version=pkg_info.version))
        file.name = "{}.pkg".format(get_random_string(12))
        response = self.client.post(
            reverse("monolith:upload_package"),
            {"file": file,
             "name": pkg_info.name.pk,
             "catalogs": [self.catalog_1.pk]},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/package_form.html")
        self.assertFormError(
            response.context["form"], "file",
            "A PkgInfo with the same name and version already exists."
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_upload_package_existing_archived_package(self, post_event):
        self._login("monolith.add_pkginfo", "monolith.view_pkginfoname", "monolith.view_pkginfo")
        pkg_info = force_pkg_info(archived=True)
        pkg_info_name = pkg_info.name
        file = BytesIO(build_dummy_package(pkg_info_name.name, pkg_info.version))
        file.name = "{}.pkg".format(get_random_string(12))
        repository = force_repository(virtual=True)
        catalog = force_catalog(repository=repository)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("monolith:upload_package"),
                {"file": file,
                 "name": pkg_info_name.pk,
                 "catalogs": [catalog.pk]},
                follow=True
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/pkg_info_name.html")
        pkg_info = pkg_info_name.pkginfo_set.first()
        self.assertTrue(pkg_info.local is True)
        self.assertEqual(pkg_info.file.name, f"monolith/packages/{pkg_info.pk:08d}.pkg")
        self.assertEqual(pkg_info.data["installer_item_location"], file.name)
        self.assertEqual(pkg_info.data["name"], pkg_info_name.name)
        self.assertEqual(
            pkg_info.data["receipts"],
            [{'installed_size': 12,
              'packageid': 'io.zentral.{}'.format(slugify(pkg_info_name.name)),
              'version': '1.0'}]
        )
        self.assertEqual(pkg_info.data["version"], "1.0")
        self.assertEqual(pkg_info.version, "1.0")
        self.assertIsNone(pkg_info.archived_at)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        event_payload_data = event.payload["object"]["new_value"].pop("data")
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "monolith.pkginfo",
                 "pk": str(pkg_info.pk),
                 "new_value": {
                     "pk": pkg_info.pk,
                     "local": True,
                     "name": pkg_info_name.name,
                     "catalogs":  [{"pk": catalog.pk, "name": catalog.name,
                                    "repository": {"pk": catalog.repository.pk,
                                                   "name": catalog.repository.name}}],
                     "requires": [],
                     "update_for": [],
                     "version": "1.0",
                     "created_at": pkg_info.created_at,
                     "updated_at": pkg_info.updated_at,
                 }
              }}
        )
        self.assertEqual(event_payload_data["name"], pkg_info_name.name)
        metadata = event.metadata.serialize()
        self.assertEqual(
            metadata["objects"],
            {"munki_pkginfo": [f"{pkg_info_name.name}|1.0"],
             "munki_pkginfo_name": [pkg_info_name.name]}
        )
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])
        pkg_info.file.delete()

    # update package

    def test_update_package_login_redirect(self):
        pkg_info = force_pkg_info()
        self._login_redirect(reverse("monolith:update_package", args=(pkg_info.pk,)))

    def test_update_package_permission_denied(self):
        pkg_info = force_pkg_info()
        self._login()
        response = self.client.get(reverse("monolith:update_package", args=(pkg_info.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_package_get_no_name(self):
        pkg_info = force_pkg_info()
        self._login("monolith.change_pkginfo")
        response = self.client.get(reverse("monolith:update_package", args=(pkg_info.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/package_form.html")
        self.assertContains(response, "Update package")
        self.assertNotIn("name", response.context["form"].fields)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_package(self, post_event):
        pkg_info = force_pkg_info()
        prev_value = pkg_info.serialize_for_event()
        self._login("monolith.change_pkginfo", "monolith.view_pkginfo", "monolith.view_pkginfoname")
        repository = force_repository(virtual=True)
        catalog = force_catalog(repository=repository)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("monolith:update_package", args=(pkg_info.pk,)),
                {"catalogs": [catalog.pk]},
                follow=True
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/pkg_info_name.html")
        pkg_info.refresh_from_db()
        self.assertTrue(pkg_info.local is True)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        new_value = copy.deepcopy(prev_value)
        new_value["updated_at"] = pkg_info.updated_at
        new_value["catalogs"] = [{"pk": catalog.pk, "name": catalog.name,
                                  "repository": {"pk": repository.pk,
                                                 "name": repository.name}}]
        new_value["requires"] = []
        new_value["update_for"] = []
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "monolith.pkginfo",
                 "pk": str(pkg_info.pk),
                 "new_value": new_value,
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(
            metadata["objects"],
            {"munki_pkginfo": [f"{pkg_info.name.name}|1.0"],
             "munki_pkginfo_name": [pkg_info.name.name]}
        )
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])

    # delete pkg info

    def test_delete_pkg_info_login_redirect(self):
        pkg_info = force_pkg_info()
        self._login_redirect(reverse("monolith:delete_pkg_info", args=(pkg_info.pk,)))

    def test_delete_pkg_info_permission_denied(self):
        pkg_info = force_pkg_info()
        self._login()
        response = self.client.get(reverse("monolith:delete_pkg_info", args=(pkg_info.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_pkg_info_404(self):
        pkg_info = force_pkg_info(local=False)
        self._login("monolith.delete_pkginfo")
        response = self.client.post(reverse("monolith:delete_pkg_info", args=(pkg_info.pk,)))
        self.assertEqual(response.status_code, 404)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_pkg_info(self, post_event):
        self._login("monolith.delete_pkginfo", "monolith.view_pkginfo", "monolith.view_pkginfoname")
        pkg_info = force_pkg_info()
        prev_value = pkg_info.serialize_for_event()
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("monolith:delete_pkg_info", args=(pkg_info.pk,)),
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/pkg_info_name.html")
        self.assertEqual(response.context["object"], pkg_info.name)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "monolith.pkginfo",
                 "pk": str(prev_value["pk"]),
                 "prev_value": prev_value
             }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(
            metadata["objects"],
            {"munki_pkginfo": [f"{pkg_info.name.name}|1.0"],
             "munki_pkginfo_name": [pkg_info.name.name]}
        )
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])

    # catalogs

    def test_catalogs_login_redirect(self):
        self._login_redirect(reverse("monolith:catalogs"))

    def test_catalogs_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:catalogs"))
        self.assertEqual(response.status_code, 403)

    def test_catalogs(self):
        self._login("monolith.view_catalog")
        response = self.client.get(reverse("monolith:catalogs"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/catalog_list.html")

    # catalog

    def test_catalog_login_redirect(self):
        catalog = force_catalog()
        self._login_redirect(reverse("monolith:catalog", args=(catalog.pk,)))

    def test_catalog_permission_denied(self):
        catalog = force_catalog()
        self._login()
        response = self.client.get(reverse("monolith:catalog", args=(catalog.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_catalog(self):
        catalog = force_catalog()
        self._login("monolith.view_catalog")
        response = self.client.get(reverse("monolith:catalog", args=(catalog.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/catalog_detail.html")
        self.assertContains(response, catalog.name)

    # create catalog

    def test_create_catalog_login_redirect(self):
        self._login_redirect(reverse("monolith:create_catalog"))

    def test_create_catalog_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:create_catalog"))
        self.assertContains(response, "Forbidden", status_code=403)

    def test_create_catalog_not_virtual_repository(self):
        repository = force_repository(virtual=False)
        self._login("monolith.add_catalog")
        response = self.client.post(reverse("monolith:create_catalog"),
                                    {"repository": repository.pk,
                                     "name": get_random_string(12)},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/catalog_form.html")
        self.assertFormError(
            response.context["form"], "repository",
            "Select a valid choice. That choice is not one of the available choices."
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_catalog(self, post_event):
        repository = force_repository(virtual=True)
        self._login("monolith.add_catalog", "monolith.view_catalog")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("monolith:create_catalog"),
                                        {"repository": repository.pk,
                                         "name": name},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/catalog_detail.html")
        catalog = response.context["object"]
        self.assertEqual(catalog.name, name)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "monolith.catalog",
                 "pk": str(catalog.pk),
                 "new_value": catalog.serialize_for_event(),
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"monolith_catalog": [str(catalog.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])

    # update catalog

    def test_update_catalog_login_redirect(self):
        repository = force_repository(virtual=True)
        catalog = force_catalog(repository=repository)
        self._login_redirect(reverse("monolith:update_catalog", args=(catalog.pk,)))

    def test_update_catalog_permission_denied(self):
        repository = force_repository(virtual=True)
        catalog = force_catalog(repository=repository)
        self._login()
        response = self.client.get(reverse("monolith:update_catalog", args=(catalog.pk,)))
        self.assertContains(response, "Forbidden", status_code=403)

    def test_update_catalog_not_virtual(self):
        repository = force_repository(virtual=False)
        catalog = force_catalog(repository=repository)
        self._login("monolith.change_catalog")
        response = self.client.get(reverse("monolith:update_catalog", args=(catalog.pk,)))
        self.assertEqual(response.status_code, 404)

    def test_update_catalog_bad_mbu(self):
        manifest = force_manifest()
        repository = force_repository(mbu=manifest.meta_business_unit, virtual=True)
        catalog = force_catalog(repository=repository, manifest=manifest)
        new_repository = force_repository(mbu=MetaBusinessUnit.objects.create(name=get_random_string(12)),
                                          virtual=True)
        self._login("monolith.change_catalog")
        response = self.client.post(reverse("monolith:update_catalog", args=(catalog.pk,)),
                                    {"repository": new_repository.pk,
                                     "name": catalog.name})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/catalog_form.html")
        self.assertFormError(
            response.context["form"], "repository",
            "This catalog is included in manifests linked to different business units than this repository."
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_catalog(self, post_event):
        repository = force_repository(virtual=True)
        catalog = force_catalog(repository=repository)
        prev_value = catalog.serialize_for_event()
        self._login("monolith.change_catalog", "monolith.view_catalog")
        new_name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("monolith:update_catalog", args=(catalog.pk,)),
                                        {"repository": repository.pk,
                                         "name": new_name},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/catalog_detail.html")
        self.assertEqual(catalog, response.context["object"])
        catalog.refresh_from_db()
        self.assertEqual(catalog.name, new_name)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "monolith.catalog",
                 "pk": str(catalog.pk),
                 "prev_value": prev_value,
                 "new_value": catalog.serialize_for_event(),
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"monolith_catalog": [str(catalog.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])

    # delete catalog

    def test_delete_catalog_login_redirect(self):
        repository = force_repository(virtual=True)
        catalog = force_catalog(repository=repository)
        self._login_redirect(reverse("monolith:delete_catalog", args=(catalog.pk,)))

    def test_delete_catalog_permission_denied(self):
        repository = force_repository(virtual=True)
        catalog = force_catalog(repository=repository)
        self._login()
        response = self.client.get(reverse("monolith:delete_catalog", args=(catalog.pk,)))
        self.assertContains(response, "Forbidden", status_code=403)

    def test_delete_catalog_cannot_be_deleted(self):
        self._login("monolith.delete_catalog")
        response = self.client.get(reverse("monolith:delete_catalog", args=(self.catalog_1.pk,)))
        self.assertEqual(response.status_code, 404)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_catalog(self, post_event):
        repository = force_repository(virtual=True)
        catalog = force_catalog(repository=repository)
        prev_pk = catalog.pk
        prev_value = catalog.serialize_for_event()
        self._login("monolith.delete_catalog", "monolith.view_catalog")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("monolith:delete_catalog", args=(catalog.pk,)),
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/catalog_list.html")
        self.assertEqual(Catalog.objects.filter(name=catalog.name).count(), 0)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "monolith.catalog",
                 "pk": str(prev_pk),
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"monolith_catalog": [str(prev_pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])

    # conditions

    def test_conditions_login_redirect(self):
        self._login_redirect(reverse("monolith:conditions"))

    def test_conditions_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:conditions"))
        self.assertEqual(response.status_code, 403)

    def test_conditions(self):
        self._login("monolith.view_condition")
        response = self.client.get(reverse("monolith:conditions"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/condition_list.html")

    # condition

    def test_condition_login_redirect(self):
        condition = Condition.objects.create(name=get_random_string(12), predicate='machine_type == "laptop"')
        self._login_redirect(reverse("monolith:condition", args=(condition.pk,)))

    def test_condition_permission_denied(self):
        condition = Condition.objects.create(name=get_random_string(12), predicate='machine_type == "laptop"')
        self._login()
        response = self.client.get(reverse("monolith:condition", args=(condition.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_condition(self):
        condition = Condition.objects.create(name=get_random_string(12), predicate='machine_type == "laptop"')
        self._login("monolith.view_condition")
        response = self.client.get(reverse("monolith:condition", args=(condition.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/condition_detail.html")
        self.assertContains(response, condition.name)
        self.assertNotContains(response, reverse("monolith:delete_condition", args=(condition.pk,)))

    def test_condition_with_delete(self):
        condition = Condition.objects.create(name=get_random_string(12), predicate='machine_type == "laptop"')
        self._login("monolith.view_condition", "monolith.delete_condition")
        response = self.client.get(reverse("monolith:condition", args=(condition.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/condition_detail.html")
        self.assertContains(response, condition.name)
        self.assertContains(response, reverse("monolith:delete_condition", args=(condition.pk,)))

    def test_condition_cannot_delete(self):
        condition = force_condition()
        force_sub_manifest_pkg_info(condition=condition)
        self._login("monolith.view_condition", "monolith.delete_condition")
        response = self.client.get(reverse("monolith:condition", args=(condition.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/condition_detail.html")
        self.assertContains(response, condition.name)
        self.assertNotContains(response, reverse("monolith:delete_condition", args=(condition.pk,)))

    # create condition

    def test_create_condition_login_redirect(self):
        self._login_redirect(reverse("monolith:create_condition"))

    def test_create_condition_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:create_condition"))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_condition(self, post_event):
        self._login("monolith.add_condition", "monolith.view_condition")
        name = get_random_string(12)
        predicate = 'machine_type == "laptop"'
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("monolith:create_condition"),
                                        {"name": name, "predicate": predicate},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/condition_detail.html")
        condition = response.context["object"]
        self.assertEqual(condition.name, name)
        self.assertEqual(condition.predicate, predicate)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "monolith.condition",
                 "pk": str(condition.pk),
                 "new_value": condition.serialize_for_event(),
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"monolith_condition": [str(condition.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])

    # update condition

    def test_update_condition_login_redirect(self):
        condition = force_condition()
        self._login_redirect(reverse("monolith:update_condition", args=(condition.pk,)))

    def test_update_condition_permission_denied(self):
        condition = force_condition()
        self._login()
        response = self.client.get(reverse("monolith:update_condition", args=(condition.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_condition(self, post_event):
        condition = Condition.objects.create(name=get_random_string(12), predicate='machine_type == "laptop"')
        prev_value = condition.serialize_for_event()
        manifest = force_manifest()
        self.assertEqual(manifest.version, 1)
        sub_manifest = force_sub_manifest(manifest=manifest)
        force_sub_manifest_pkg_info(sub_manifest=sub_manifest, condition=condition)
        self._login("monolith.change_condition", "monolith.view_condition")
        new_name = get_random_string(12)
        new_predicate = 'machine_type == "desktop"'
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("monolith:update_condition", args=(condition.pk,)),
                                        {"name": new_name, "predicate": new_predicate},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/condition_detail.html")
        self.assertEqual(condition, response.context["object"])
        condition.refresh_from_db()
        self.assertEqual(condition.name, new_name)
        self.assertEqual(condition.predicate, new_predicate)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "monolith.condition",
                 "pk": str(condition.pk),
                 "prev_value": prev_value,
                 "new_value": condition.serialize_for_event(),
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"monolith_condition": [str(condition.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 2)

    # delete condition

    def test_delete_condition_login_redirect(self):
        condition = Condition.objects.create(name=get_random_string(12), predicate='machine_type == "laptop"')
        self._login_redirect(reverse("monolith:delete_condition", args=(condition.pk,)))

    def test_delete_condition_permission_denied(self):
        condition = Condition.objects.create(name=get_random_string(12), predicate='machine_type == "laptop"')
        self._login()
        response = self.client.get(reverse("monolith:delete_condition", args=(condition.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_condition_get(self):
        condition = Condition.objects.create(name=get_random_string(12), predicate='machine_type == "laptop"')
        self._login("monolith.delete_condition")
        response = self.client.get(reverse("monolith:delete_condition", args=(condition.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/condition_confirm_delete.html")

    def test_delete_condition_cannot_delete(self):
        condition = force_condition()
        force_sub_manifest_pkg_info(condition=condition)
        self._login("monolith.delete_condition")
        response = self.client.get(reverse("monolith:delete_condition", args=(condition.pk,)))
        self.assertEqual(response.status_code, 404)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_condition_post(self, post_event):
        condition = Condition.objects.create(name=get_random_string(12), predicate='machine_type == "laptop"')
        prev_pk = condition.pk
        prev_value = condition.serialize_for_event()
        self._login("monolith.view_condition", "monolith.delete_condition")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("monolith:delete_condition", args=(condition.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/condition_list.html")
        self.assertEqual(Condition.objects.filter(pk=condition.pk).count(), 0)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "monolith.condition",
                 "pk": str(prev_pk),
                 "prev_value": prev_value
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"monolith_condition": [str(prev_pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])

    def test_delete_condition_get_blocked(self):
        condition = Condition.objects.create(name=get_random_string(12), predicate='machine_type == "laptop"')
        force_sub_manifest_pkg_info(condition=condition)
        self._login("monolith.view_condition", "monolith.delete_condition")
        response = self.client.get(reverse("monolith:delete_condition", args=(condition.pk,)), follow=True)
        self.assertEqual(response.status_code, 404)

    def test_delete_condition_post_blocked(self):
        condition = Condition.objects.create(name=get_random_string(12), predicate='machine_type == "laptop"')
        force_sub_manifest_pkg_info(condition=condition)
        self._login("monolith.view_condition", "monolith.delete_condition")
        response = self.client.post(reverse("monolith:delete_condition", args=(condition.pk,)), follow=True)
        self.assertEqual(response.status_code, 404)

    # sub manifests

    def test_sub_manifests_login_redirect(self):
        self._login_redirect(reverse("monolith:sub_manifests"))

    def test_sub_manifests_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:sub_manifests"))
        self.assertEqual(response.status_code, 403)

    def test_sub_manifests(self):
        self._login("monolith.view_submanifest")
        sub_manifest = force_sub_manifest()
        response = self.client.get(reverse("monolith:sub_manifests"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, sub_manifest.name)

    def test_sub_manifests_search(self):
        self._login("monolith.view_submanifest")
        response = self.client.get(reverse("monolith:sub_manifests"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/sub_manifest_list.html")
        self.assertNotContains(response, "We didn't find any item related to your search")
        sub_manifest = force_sub_manifest()
        response = self.client.get(reverse("monolith:sub_manifests"), {"keywords": "does not exists"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/sub_manifest_list.html")
        self.assertContains(response, "We didn't find any item related to your search")
        self.assertContains(response, reverse("monolith:sub_manifests") + '">all the items')
        response = self.client.get(reverse("monolith:sub_manifests"), {"keywords": sub_manifest.name})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/sub_manifest_list.html")
        self.assertNotContains(response, "We didn't find any item related to your search")

    # sub manifest

    def test_sub_manifest_login_redirect(self):
        sub_manifest = force_sub_manifest()
        self._login_redirect(reverse("monolith:sub_manifest", args=(sub_manifest.pk,)))

    def test_sub_manifest_permission_denied(self):
        sub_manifest = force_sub_manifest()
        self._login()
        response = self.client.get(reverse("monolith:sub_manifest", args=(sub_manifest.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_sub_manifest_no_pkginfo_links(self):
        smpi = force_sub_manifest_pkg_info()
        self._login("monolith.view_submanifest")
        response = self.client.get(reverse("monolith:sub_manifest", args=(smpi.sub_manifest.pk,)))
        self.assertTemplateUsed(response, "monolith/sub_manifest.html")
        self.assertNotContains(response, 'class="danger"')
        self.assertContains(response, "Package (1)")
        self.assertNotContains(
            response,
            reverse("monolith:sub_manifest_add_pkg_info",
                    args=(smpi.sub_manifest.pk,))
        )
        self.assertNotContains(
            response,
            reverse("monolith:update_sub_manifest_pkg_info",
                    args=(smpi.sub_manifest.pk, smpi.pk))
        )
        self.assertNotContains(
            response,
            reverse("monolith:delete_sub_manifest_pkg_info",
                    args=(smpi.sub_manifest.pk, smpi.pk))
        )

    def test_sub_manifest_pkginfo_edit_link(self):
        smpi = force_sub_manifest_pkg_info()
        self._login("monolith.view_submanifest", "monolith.change_submanifestpkginfo")
        response = self.client.get(reverse("monolith:sub_manifest", args=(smpi.sub_manifest.pk,)))
        self.assertTemplateUsed(response, "monolith/sub_manifest.html")
        self.assertNotContains(response, 'class="danger"')
        self.assertContains(response, "Package (1)")
        self.assertNotContains(
            response,
            reverse("monolith:sub_manifest_add_pkg_info",
                    args=(smpi.sub_manifest.pk,))
        )
        self.assertContains(
            response,
            reverse("monolith:update_sub_manifest_pkg_info",
                    args=(smpi.sub_manifest.pk, smpi.pk))
        )
        self.assertNotContains(
            response,
            reverse("monolith:delete_sub_manifest_pkg_info",
                    args=(smpi.sub_manifest.pk, smpi.pk))
        )

    def test_sub_manifest_pkginfo_add_link(self):
        smpi = force_sub_manifest_pkg_info()
        self._login("monolith.view_submanifest", "monolith.add_submanifestpkginfo")
        response = self.client.get(reverse("monolith:sub_manifest", args=(smpi.sub_manifest.pk,)))
        self.assertTemplateUsed(response, "monolith/sub_manifest.html")
        self.assertNotContains(response, 'class="danger"')
        self.assertContains(response, "Package (1)")
        self.assertContains(
            response,
            reverse("monolith:sub_manifest_add_pkg_info",
                    args=(smpi.sub_manifest.pk,))
        )
        self.assertNotContains(
            response,
            reverse("monolith:update_sub_manifest_pkg_info",
                    args=(smpi.sub_manifest.pk, smpi.pk))
        )
        self.assertNotContains(
            response,
            reverse("monolith:delete_sub_manifest_pkg_info",
                    args=(smpi.sub_manifest.pk, smpi.pk))
        )

    def test_sub_manifest_pkginfo_delete_link(self):
        smpi = force_sub_manifest_pkg_info()
        self._login("monolith.view_submanifest", "monolith.delete_submanifestpkginfo")
        response = self.client.get(reverse("monolith:sub_manifest", args=(smpi.sub_manifest.pk,)))
        self.assertTemplateUsed(response, "monolith/sub_manifest.html")
        self.assertNotContains(response, 'class="danger"')
        self.assertContains(response, "Package (1)")
        self.assertNotContains(
            response,
            reverse("monolith:sub_manifest_add_pkg_info",
                    args=(smpi.sub_manifest.pk,))
        )
        self.assertNotContains(
            response,
            reverse("monolith:update_sub_manifest_pkg_info",
                    args=(smpi.sub_manifest.pk, smpi.pk))
        )
        self.assertContains(
            response,
            reverse("monolith:delete_sub_manifest_pkg_info",
                    args=(smpi.sub_manifest.pk, smpi.pk))
        )

    def test_sub_manifest_pkginfo_archived_no_edit_link(self):
        smpi = force_sub_manifest_pkg_info(archived=True)
        self._login("monolith.view_submanifest", "monolith.change_submanifestpkginfo")
        response = self.client.get(reverse("monolith:sub_manifest", args=(smpi.sub_manifest.pk,)))
        self.assertTemplateUsed(response, "monolith/sub_manifest.html")
        self.assertContains(response, 'class="data-row danger"')
        self.assertNotContains(
            response,
            reverse("monolith:update_sub_manifest_pkg_info",
                    args=(smpi.sub_manifest.pk, smpi.pk))
        )

    # create submanifest

    def test_create_submanifest_redirect(self):
        self._login_redirect(reverse("monolith:create_sub_manifest"))

    def test_create_submanifest_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:create_sub_manifest"))
        self.assertEqual(response.status_code, 403)

    def test_create_submanifest_get(self):
        self._login("monolith.add_submanifest")
        response = self.client.get(reverse("monolith:create_sub_manifest"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/edit_sub_manifest.html")

    def test_create_submanifest_post(self):
        self._login("monolith.add_submanifest", "monolith.view_submanifest")
        name = get_random_string(12)
        response = self.client.post(reverse("monolith:create_sub_manifest"),
                                    {"name": name},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/sub_manifest.html")
        self.assertEqual(response.context["object"].name, name)

    # add submanifest pkginfo

    def test_add_sub_manifest_pkg_info_redirect(self):
        sub_manifest = force_sub_manifest()
        self._login_redirect(reverse("monolith:sub_manifest_add_pkg_info", args=(sub_manifest.pk,)))

    def test_add_sub_manifest_pkg_info_permission_denied(self):
        sub_manifest = force_sub_manifest()
        self._login()
        response = self.client.get(reverse("monolith:sub_manifest_add_pkg_info", args=(sub_manifest.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_add_sub_manifest_pkg_info_get(self):
        sub_manifest = force_sub_manifest()
        self._login("monolith.add_submanifestpkginfo")
        response = self.client.get(reverse("monolith:sub_manifest_add_pkg_info", args=(sub_manifest.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/edit_sub_manifest_pkg_info.html")

    def test_add_sub_manifest_pkg_info_post_pkg_info_name_already_included(self):
        smpi = force_sub_manifest_pkg_info()
        self._login("monolith.add_submanifestpkginfo")
        response = self.client.post(
            reverse("monolith:sub_manifest_add_pkg_info", args=(smpi.sub_manifest.pk,)),
            {"pkg_info_name": smpi.pkg_info_name,
             "key": "managed_installs"},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/edit_sub_manifest_pkg_info.html")
        self.assertFormError(
            response.context["form"], "pkg_info_name",
            "Select a valid choice. That choice is not one of the available choices."
        )

    def test_add_sub_manifest_pkg_info_post_featured_item_error(self):
        sub_manifest = force_sub_manifest()
        self._login("monolith.add_submanifestpkginfo")
        pkginfo_name = PkgInfoName.objects.create(name=get_random_string(12))
        PkgInfo.objects.create(repository=force_repository(),
                               name=pkginfo_name, version="1.0",
                               data={"name": pkginfo_name.name,
                                     "version": "1.0"})
        response = self.client.post(
            reverse("monolith:sub_manifest_add_pkg_info", args=(sub_manifest.pk,)),
            {"pkg_info_name": pkginfo_name.pk,
             "key": "managed_installs",
             "featured_item": "on"},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/edit_sub_manifest_pkg_info.html")
        self.assertFormError(response.context["form"], "featured_item", "Only optional install items can be featured")

    def test_add_sub_manifest_pkg_info_post(self):
        sub_manifest = force_sub_manifest()
        self._login("monolith.add_submanifestpkginfo", "monolith.view_submanifest")
        pkginfo_name = force_name()
        PkgInfo.objects.create(repository=force_repository(),
                               name=pkginfo_name, version="1.0",
                               data={"name": pkginfo_name.name,
                                     "version": "1.0"})
        response = self.client.post(
            reverse("monolith:sub_manifest_add_pkg_info", args=(sub_manifest.pk,)),
            {"pkg_info_name": pkginfo_name.pk,
             "key": "optional_installs",
             "featured_item": "on"},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/sub_manifest.html")
        self.assertContains(response, pkginfo_name.name)

    def test_add_default_install_sub_manifest_pkg_info_shard(self):
        sub_manifest = force_sub_manifest()
        self._login("monolith.add_submanifestpkginfo", "monolith.view_submanifest")
        pkginfo_name = force_name()
        PkgInfo.objects.create(repository=force_repository(),
                               name=pkginfo_name, version="1.0",
                               data={"name": pkginfo_name.name,
                                     "version": "1.0"})
        response = self.client.post(
            reverse("monolith:sub_manifest_add_pkg_info", args=(sub_manifest.pk,)),
            {"pkg_info_name": pkginfo_name.pk,
             "key": "default_installs",
             "featured_item": "on",
             "default_shard": 90,
             "shard_modulo": 100},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/sub_manifest.html")
        self.assertContains(response, pkginfo_name.name)
        smpi = sub_manifest.submanifestpkginfo_set.get(pkg_info_name=pkginfo_name)
        self.assertEqual(smpi.options, {"shards": {"default": 90, "modulo": 100}})

    # delete submanifest pkginfo

    def test_delete_sub_manifest_pkg_info_redirect(self):
        smpi = force_sub_manifest_pkg_info()
        self._login_redirect(reverse("monolith:delete_sub_manifest_pkg_info",
                                     args=(smpi.sub_manifest.pk, smpi.pk)))

    def test_delete_sub_manifest_pkg_info_permission_denied(self):
        smpi = force_sub_manifest_pkg_info()
        self._login()
        response = self.client.get(reverse("monolith:delete_sub_manifest_pkg_info",
                                           args=(smpi.sub_manifest.pk, smpi.pk)))
        self.assertEqual(response.status_code, 403)

    def test_delete_sub_manifest_pkg_info_get(self):
        smpi = force_sub_manifest_pkg_info()
        self._login("monolith.delete_submanifestpkginfo", "monolith.view_submanifest")
        response = self.client.get(reverse("monolith:delete_sub_manifest_pkg_info",
                                           args=(smpi.sub_manifest.pk, smpi.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/delete_sub_manifest_pkg_info.html")

    def test_delete_sub_manifest_pkg_info_post(self):
        manifest = force_manifest()
        self.assertEqual(manifest.version, 1)
        sub_manifest = force_sub_manifest(manifest=manifest)
        smpi = force_sub_manifest_pkg_info(sub_manifest=sub_manifest)
        self._login("monolith.delete_submanifestpkginfo", "monolith.view_submanifest")
        response = self.client.post(reverse("monolith:delete_sub_manifest_pkg_info",
                                            args=(sub_manifest.pk, smpi.pk)),
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/sub_manifest.html")
        self.assertEqual(response.context["object"], sub_manifest)
        self.assertEqual(sub_manifest.submanifestpkginfo_set.count(), 0)
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 2)

    # manifests

    def test_manifests_login_redirect(self):
        self._login_redirect(reverse("monolith:manifests"))

    def test_manifests_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:manifests"))
        self.assertEqual(response.status_code, 403)

    def test_manifests(self):
        self._login("monolith.view_manifest")
        response = self.client.get(reverse("monolith:manifests"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/manifest_list.html")
        self.assertEqual(response.context["object_list"][0], self.manifest)

    # manifest

    def test_manifest_login_redirect(self):
        self._login_redirect(reverse("monolith:manifest", args=(self.manifest.pk,)))

    def test_manifest_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:manifest", args=(self.manifest.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_manifest(self):
        self._login("monolith.view_manifest")
        response = self.client.get(reverse("monolith:manifest", args=(self.manifest.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/manifest.html")
        self.assertEqual(response.context["object"], self.manifest)
        self.assertNotContains(
            response, reverse("monolith_api:enrollment_plist", args=(self.enrollment.pk,)))
        self.assertNotContains(
            response, reverse("monolith_api:enrollment_configuration_profile", args=(self.enrollment.pk,)))

    def test_manifest_with_enrollments(self):
        self._login("monolith.view_manifest", "monolith.view_enrollment")
        response = self.client.get(reverse("monolith:manifest", args=(self.manifest.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/manifest.html")
        self.assertEqual(response.context["object"], self.manifest)
        self.assertContains(
            response, reverse("monolith_api:enrollment_plist", args=(self.enrollment.pk,)))
        self.assertContains(
            response, reverse("monolith_api:enrollment_configuration_profile", args=(self.enrollment.pk,)))

    def test_manifest_search(self):
        self._login("monolith.view_manifest")
        response = self.client.get(reverse("monolith:manifests"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/manifest_list.html")
        self.assertNotContains(response, "We didn't find any item related to your search")
        manifest = force_manifest()
        response = self.client.get(reverse("monolith:manifests"), {"name": manifest.name}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/manifest.html")
        self.assertContains(response, manifest.name)
        self.assertNotContains(response, "We didn't find any item related to your search")
        response = self.client.get(reverse("monolith:manifests"), {"name": "does not exists"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/manifest_list.html")
        self.assertContains(response, "We didn't find any item related to your search")
        self.assertContains(response, reverse("monolith:manifests") + '">all the items')

    # create manifest

    def test_create_manifest_login_redirect(self):
        self._login_redirect(reverse("monolith:create_manifest"))

    def test_create_manifest_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:create_manifest"))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_manifest(self, post_event):
        self._login("monolith.add_manifest", "monolith.view_manifest")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("monolith:create_manifest"),
                                        {"name": name,
                                         "meta_business_unit": self.mbu.pk},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/manifest.html")
        manifest = response.context["object"]
        self.assertEqual(manifest.name, name)
        self.assertEqual(manifest.meta_business_unit, self.mbu)
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
                     "meta_business_unit": {"pk": self.mbu.pk, "name": self.mbu.name},
                     "version": 1,
                     "created_at": manifest.created_at,
                     "updated_at": manifest.updated_at,
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"monolith_manifest": [str(manifest.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])

    # update manifest

    def test_update_manifest_login_redirect(self):
        manifest = force_manifest()
        self._login_redirect(reverse("monolith:update_manifest", args=(manifest.pk,)))

    def test_update_manifest_permission_denied(self):
        manifest = force_manifest()
        self._login()
        response = self.client.get(reverse("monolith:update_manifest", args=(manifest.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_manifest(self, post_event):
        manifest = force_manifest()
        prev_value = manifest.serialize_for_event()
        self._login("monolith.change_manifest", "monolith.view_manifest")
        new_name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("monolith:update_manifest", args=(manifest.pk,)),
                                        {"name": new_name,
                                         "meta_business_unit": self.mbu.pk},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/manifest.html")
        manifest = response.context["object"]
        self.assertEqual(manifest.name, new_name)
        self.assertEqual(manifest.meta_business_unit, self.mbu)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "monolith.manifest",
                 "pk": str(manifest.pk),
                 "new_value": {
                     "pk": manifest.pk,
                     "name": new_name,
                     "meta_business_unit": {"pk": self.mbu.pk, "name": self.mbu.name},
                     "version": 1,  # not incremented!
                     "created_at": manifest.created_at,
                     "updated_at": manifest.updated_at,
                 },
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"monolith_manifest": [str(manifest.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])

    # manifest machine info

    def test_manifest_machine_info_redirect(self):
        self._login_redirect(reverse("monolith:manifest_machine_info", args=(self.manifest.pk,))
                             + "?serial_number=" + self.serial_number)

    def test_manifest_machine_info_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:manifest_machine_info", args=(self.manifest.pk,))
                                   + "?serial_number=" + self.serial_number)
        self.assertEqual(response.status_code, 403)

    def test_manifest_machine_info_not_found(self):
        self._login("monolith.view_manifest", "monolith.view_pkginfo")
        response = self.client.get(reverse("monolith:manifest_machine_info", args=(self.manifest.pk,)))
        self.assertEqual(response.status_code, 404)

    def test_manifest_machine_info(self):
        self._login("monolith.view_manifest", "monolith.view_pkginfo")
        response = self.client.get(reverse("monolith:manifest_machine_info", args=(self.manifest.pk,))
                                   + "?serial_number=" + self.serial_number)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/machine_info.html")
        self.assertEqual(response.context["machine"].serial_number, self.serial_number)
        self.assertEqual(
            response.context["packages"],
            [('aaaa first name',
              {'pkgsinfo': [({'name': 'aaaa first name',
                              'version': '1.0',
                              'icon_name': f'icon.{self.pkginfo_1_1.pk}.aaaa-first-name.png'},
                             'installed',
                             [],
                             None,
                             None,
                             [],
                             True)]})]
        )

    # terraform export

    def test_terraform_export_redirect(self):
        self._login_redirect(reverse("monolith:terraform_export"))

    def test_terraform_export_permission_denied(self):
        self._login("monolith.view_manifest")  # no enough
        response = self.client.get(reverse("monolith:terraform_export"))
        self.assertEqual(response.status_code, 403)

    def test_terraform_export(self):
        self._login(
            "monolith.view_catalog",
            "monolith.view_condition",
            "monolith.view_enrollment",
            "monolith.view_manifest",
            "monolith.view_submanifest",
        )
        force_catalog()
        condition = force_condition()
        force_manifest()
        force_sub_manifest_pkg_info(condition=condition)
        response = self.client.get(reverse("monolith:terraform_export"))
        self.assertEqual(response.status_code, 200)

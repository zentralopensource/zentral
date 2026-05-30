import hashlib
import os
import tempfile
import uuid
from functools import lru_cache
from unittest.mock import Mock, patch

from accounts.models import APIToken, User
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from tests.utils.packages import build_dummy_package
from tests.zentral_test_utils.login_case import LoginCase
from tests.zentral_test_utils.request_case import RequestCase
from zentral.contrib.mdm.app_manifest import read_package_info
from zentral.contrib.mdm.models import (
    Artifact,
    ArtifactVersion,
    Channel,
    Declaration,
    Package,
    PackageRef,
    Platform,
)
from zentral.core.events.base import AuditEvent


class MDMPackagesAPIViewsTestCase(TestCase, LoginCase, RequestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True,
        )
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        cls.user.groups.set([cls.group])
        _, cls.api_key = APIToken.objects.create_for_user(cls.service_account)

    # LoginCase

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "mdm_api"

    # RequestCase

    def _get_api_key(self):
        return self.api_key

    # helpers

    @lru_cache
    def _build_package_file(self, name="apitest"):
        content = build_dummy_package(name=name, version="1.0", product_archive_title=name)
        file = tempfile.NamedTemporaryFile(suffix=".pkg")
        file.write(content)
        sha256 = hashlib.sha256(content).hexdigest()
        return file, sha256, len(content)

    def _force_package(self, name=None):
        name = name or get_random_string(12)
        file, sha256, size = self._build_package_file(name="forced")
        file.seek(0)
        _, _, pkg_data = read_package_info(file, compute_sha256=True)
        file.seek(0)
        # one Package per test (sha256 unique) — derive a per-instance sha256
        # by hashing the random name into the synthetic value.
        synthetic_sha = hashlib.sha256(f"{name}-{get_random_string(8)}".encode()).hexdigest()
        from django.core.files.uploadedfile import SimpleUploadedFile
        uploaded = SimpleUploadedFile(f"{name}.pkg", file.read())
        return Package.objects.create(
            name=name,
            description="",
            type=Package.Type.PKG,
            file=uploaded,
            filename=uploaded.name,
            sha256=synthetic_sha,
            size=pkg_data["package_size"],
            product_id=pkg_data["product_id"],
            product_version=pkg_data["product_version"],
            bundles=pkg_data["bundles"],
            manifest=pkg_data["manifest"],
            source_uri="",
        )

    # list

    def test_list_packages_unauthorized(self):
        response = self.get(reverse("mdm_api:packages"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_packages_permission_denied(self):
        response = self.get(reverse("mdm_api:packages"))
        self.assertEqual(response.status_code, 403)

    def test_list_packages_empty(self):
        self.set_permissions("mdm.view_package")
        response = self.get(reverse("mdm_api:packages"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["results"], [])

    def test_list_packages(self):
        package = self._force_package()
        self.set_permissions("mdm.view_package")
        response = self.get(reverse("mdm_api:packages"))
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["count"], 1)
        result = payload["results"][0]
        self.assertEqual(result["id"], str(package.id))
        self.assertEqual(result["name"], package.name)
        self.assertEqual(result["type"], "PKG")
        self.assertEqual(result["sha256"], package.sha256)
        self.assertEqual(result["product_id"], package.product_id)

    # create

    def test_create_package_unauthorized(self):
        response = self.post(
            reverse("mdm_api:packages"),
            data={"name": "x", "source_uri": "s3://b/k.pkg", "sha256": 64 * "0"},
            include_token=False,
        )
        self.assertEqual(response.status_code, 401)

    def test_create_package_permission_denied(self):
        response = self.post(
            reverse("mdm_api:packages"),
            data={"name": "x", "source_uri": "s3://b/k.pkg", "sha256": 64 * "0"},
        )
        self.assertEqual(response.status_code, 403)

    def test_create_package_missing_source_uri(self):
        self.set_permissions("mdm.add_package")
        response = self.post(
            reverse("mdm_api:packages"),
            data={"name": "x"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("source_uri", response.json())

    def test_create_package_missing_sha256(self):
        self.set_permissions("mdm.add_package")
        response = self.post(
            reverse("mdm_api:packages"),
            data={"name": "x", "source_uri": "s3://b/k.pkg"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("sha256", response.json())

    def test_create_package_unknown_scheme(self):
        self.set_permissions("mdm.add_package")
        response = self.post(
            reverse("mdm_api:packages"),
            data={"name": "x", "source_uri": "ftp://b/k.pkg", "sha256": 64 * "0"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"source_uri": ["Unknown external resource URI scheme: 'ftp'"]})

    def test_create_package_unsupported_extension(self):
        self.set_permissions("mdm.add_package")
        response = self.post(
            reverse("mdm_api:packages"),
            data={"name": "x", "source_uri": "s3://b/k.dmg", "sha256": 64 * "0"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"source_uri": ["Unsupported file extension: '.dmg'"]})

    @patch("zentral.utils.external_resources.boto3.client")
    def test_create_package_s3_error(self, boto3_client):
        # S3 / boto3 raise their own exception types (botocore.exceptions.*),
        # not ValueError. The server must NOT echo the raw exception message
        # to the client (CodeQL py/stack-trace-exposure).
        boom = Mock()
        boom.download_fileobj.side_effect = RuntimeError("Boom!!! /internal/path /more/state")
        boto3_client.return_value = boom
        self.set_permissions("mdm.add_package")
        with patch.dict(os.environ, {"AWS_REGION": "eu-central-17"}):
            response = self.post(
                reverse("mdm_api:packages"),
                data={"name": "x", "source_uri": "s3://yolo/fomo.pkg", "sha256": 64 * "0"},
            )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {"source_uri": ["Could not download or validate the package."]},
        )
        # Raw exception state must not leak.
        self.assertNotIn("Boom", response.content.decode())
        self.assertNotIn("/internal/path", response.content.decode())

    @patch("zentral.utils.external_resources.download_s3_external_resource")
    def test_create_package_hash_mismatch(self, download_s3_external_resource):
        file, _, _ = self._build_package_file()
        file.seek(0)
        download_s3_external_resource.return_value = file
        self.set_permissions("mdm.add_package")
        response = self.post(
            reverse("mdm_api:packages"),
            data={"name": "x", "source_uri": "s3://b/k.pkg", "sha256": 64 * "0"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"source_uri": ["Hash mismatch"]})

    @patch("zentral.utils.external_resources.download_s3_external_resource")
    def test_create_package_duplicate_sha256(self, download_s3_external_resource):
        file, sha256, _ = self._build_package_file()
        # pre-existing row with the same sha256 the upload will hash to
        Package.objects.filter(sha256=sha256).delete()
        file.seek(0)
        download_s3_external_resource.return_value = file
        # First, create one through the API
        self.set_permissions("mdm.add_package", "mdm.view_package")
        response = self.post(
            reverse("mdm_api:packages"),
            data={"name": "first", "source_uri": "s3://b/k.pkg", "sha256": sha256},
        )
        self.assertEqual(response.status_code, 201)
        # Re-uploading the same file under a different name should be rejected
        file.seek(0)
        download_s3_external_resource.return_value = file
        response = self.post(
            reverse("mdm_api:packages"),
            data={"name": "second", "source_uri": "s3://b/k.pkg", "sha256": sha256},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"sha256": ["A package with the same SHA256 already exists."]})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("zentral.utils.external_resources.download_s3_external_resource")
    def test_create_package(self, download_s3_external_resource, post_event):
        file, sha256, size = self._build_package_file()
        Package.objects.filter(sha256=sha256).delete()
        file.seek(0)
        download_s3_external_resource.return_value = file
        self.set_permissions("mdm.add_package", "mdm.view_package")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("mdm_api:packages"),
                data={
                    "name": "API Package",
                    "description": "made via the API",
                    "source_uri": "s3://yolo/fomo.pkg",
                    "sha256": sha256,
                },
            )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        data = response.json()
        self.assertEqual(data["name"], "API Package")
        self.assertEqual(data["description"], "made via the API")
        self.assertEqual(data["source_uri"], "s3://yolo/fomo.pkg")
        self.assertEqual(data["sha256"], sha256)
        self.assertEqual(data["size"], size)
        self.assertEqual(data["filename"], "fomo.pkg")
        self.assertEqual(data["type"], "PKG")
        self.assertEqual(data["product_id"], "io.zentral.apitest")
        package = Package.objects.get(pk=data["id"])
        self.assertEqual(package.sha256, sha256)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(event.payload["action"], "created")
        self.assertEqual(event.payload["object"]["model"], "mdm.package")
        self.assertEqual(event.payload["object"]["pk"], str(package.id))

    # retrieve

    def test_get_package(self):
        package = self._force_package()
        self.set_permissions("mdm.view_package")
        response = self.get(reverse("mdm_api:package", args=(package.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["id"], str(package.pk))

    def test_get_package_404(self):
        self.set_permissions("mdm.view_package")
        response = self.get(reverse("mdm_api:package", args=(uuid.uuid4(),)))
        self.assertEqual(response.status_code, 404)

    # update

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_package_name_description(self, post_event):
        package = self._force_package()
        self.set_permissions("mdm.change_package", "mdm.view_package")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(
                reverse("mdm_api:package", args=(package.pk,)),
                data={"name": "renamed", "description": "new"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        package.refresh_from_db()
        self.assertEqual(package.name, "renamed")
        self.assertEqual(package.description, "new")
        # event
        event = post_event.call_args_list[0].args[0]
        self.assertEqual(event.payload["action"], "updated")

    def test_update_package_rejects_source_uri_change(self):
        package = self._force_package()
        self.set_permissions("mdm.change_package")
        response = self.put(
            reverse("mdm_api:package", args=(package.pk,)),
            data={"name": package.name, "source_uri": "s3://different/file.pkg"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"source_uri": ["Cannot be changed after creation."]})

    def test_update_package_rejects_sha256_change(self):
        package = self._force_package()
        self.set_permissions("mdm.change_package")
        response = self.put(
            reverse("mdm_api:package", args=(package.pk,)),
            data={"name": package.name, "sha256": 64 * "f"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"sha256": ["Cannot be changed after creation."]})

    # delete

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_package(self, post_event):
        package = self._force_package()
        pk = package.pk
        self.set_permissions("mdm.delete_package")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("mdm_api:package", args=(pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(len(callbacks), 1)
        self.assertFalse(Package.objects.filter(pk=pk).exists())
        event = post_event.call_args_list[0].args[0]
        self.assertEqual(event.payload["action"], "deleted")

    def test_delete_package_blocked_when_referenced(self):
        package = self._force_package()
        artifact = Artifact.objects.create(
            name=get_random_string(12),
            type=Artifact.Type.CONFIGURATION,
            channel=Channel.DEVICE,
            platforms=[Platform.MACOS],
        )
        artifact_version = ArtifactVersion.objects.create(artifact=artifact, version=1, macos=True)
        declaration = Declaration.objects.create(
            artifact_version=artifact_version,
            type="com.apple.configuration.package",
            identifier=get_random_string(12),
            server_token=get_random_string(12),
            payload={"ManifestURL": f"ztl:{package.pk}"},
        )
        PackageRef.objects.create(declaration=declaration, key=("ManifestURL",), package=package)
        self.set_permissions("mdm.delete_package")
        response = self.delete(reverse("mdm_api:package", args=(package.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertIn("cannot be deleted", str(response.content))
        self.assertTrue(Package.objects.filter(pk=package.pk).exists())

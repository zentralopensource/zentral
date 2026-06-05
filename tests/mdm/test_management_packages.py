from functools import lru_cache
from io import BytesIO
from unittest.mock import patch

from accounts.models import User
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from tests.utils.packages import build_dummy_package
from tests.zentral_test_utils.login_case import LoginCase
from zentral.contrib.mdm.models import Package
from zentral.core.events.base import AuditEvent

from .utils import build_test_package_file, force_package


class PackageManagementViewsTestCase(TestCase, LoginCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "mdm"

    # helpers

    @lru_cache
    def _build_package(self, name="test123", version="1.0"):
        package = BytesIO(build_dummy_package(name=name, version=version, product_archive_title=name))
        package.name = f"{name}.pkg"
        return package

    # model

    def test_serialize_for_event_keys_only(self):
        package = force_package(description="ignored")
        d = package.serialize_for_event(keys_only=True)
        self.assertEqual(d, {"pk": str(package.id), "name": package.name})

    def test_post_delete_package_swallows_storage_failure(self):
        package = force_package()
        with patch.object(package.file, "delete", side_effect=OSError("storage gone")):
            with self.assertLogs("zentral.contrib.mdm.models", level="ERROR") as captured:
                package.delete()
        self.assertTrue(any("Could not delete package file" in r for r in captured.output))

    # form

    def test_create_package_form_short_circuits_when_no_file(self):
        from zentral.contrib.mdm.forms import CreatePackageForm
        form = CreatePackageForm(data={"name": "foo", "description": ""}, files={})
        # invalid because "file" is required, but clean() must return without
        # raising — the "no uploaded file" early-return is the path under test.
        self.assertFalse(form.is_valid())
        self.assertIn("file", form.errors)

    # list

    def test_packages_redirect(self):
        self.login_redirect("packages")

    def test_packages_permission_denied(self):
        self.login()
        response = self.client.get(reverse("mdm:packages"))
        self.assertEqual(response.status_code, 403)

    def test_packages_empty(self):
        self.login("mdm.view_package")
        response = self.client.get(reverse("mdm:packages"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/package_list.html")

    def test_packages_no_links(self):
        package = force_package()
        self.login("mdm.view_package")
        response = self.client.get(reverse("mdm:packages"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/package_list.html")
        self.assertContains(response, package.name)
        self.assertNotContains(response, reverse("mdm:update_package", args=(package.pk,)))
        self.assertNotContains(response, reverse("mdm:delete_package", args=(package.pk,)))

    def test_packages_all_links(self):
        package = force_package()
        self.login("mdm.view_package", "mdm.change_package", "mdm.delete_package")
        response = self.client.get(reverse("mdm:packages"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("mdm:update_package", args=(package.pk,)))
        self.assertContains(response, reverse("mdm:delete_package", args=(package.pk,)))

    # detail

    def test_package_redirect(self):
        package = force_package()
        self.login_redirect("package", package.pk)

    def test_package_permission_denied(self):
        package = force_package()
        self.login()
        response = self.client.get(reverse("mdm:package", args=(package.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_package_get(self):
        package = force_package(description="some description")
        self.login("mdm.view_package")
        response = self.client.get(reverse("mdm:package", args=(package.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/package_detail.html")
        self.assertContains(response, package.name)
        self.assertContains(response, "some description")
        self.assertContains(response, package.product_id)
        # UUID is rendered for easy copying.
        self.assertContains(response, str(package.id))
        # cross-link section is present, empty
        self.assertContains(response, "Referenced by 0 declarations")

    def test_package_detail_lists_referencing_artifact_versions(self):
        from zentral.contrib.mdm.models import (
            Artifact, ArtifactVersion, Channel, Declaration, PackageRef, Platform,
        )
        package = force_package()
        artifact = Artifact.objects.create(
            name="ref-artifact",
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
        self.login("mdm.view_package", "mdm.view_artifact", "mdm.view_artifactversion")
        response = self.client.get(reverse("mdm:package", args=(package.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Referenced by 1 declaration")
        self.assertContains(response, reverse("mdm:artifact", args=(artifact.pk,)))
        self.assertContains(response, reverse("mdm:artifact_version", args=(artifact.pk, artifact_version.pk)))
        self.assertContains(response, "ref-artifact")

    # create

    def test_create_package_redirect(self):
        self.login_redirect("create_package")

    def test_create_package_permission_denied(self):
        self.login()
        response = self.client.get(reverse("mdm:create_package"))
        self.assertEqual(response.status_code, 403)

    def test_create_package_get(self):
        self.login("mdm.add_package")
        response = self.client.get(reverse("mdm:create_package"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/package_form.html")
        self.assertContains(response, "Create package")

    def test_create_package_post_invalid_package(self):
        notapackage = BytesIO(b"-")
        notapackage.name = "test.pkg"
        self.login("mdm.add_package", "mdm.view_package")
        response = self.client.post(reverse("mdm:create_package"),
                                    {"name": "Foo", "description": "", "file": notapackage},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/package_form.html")
        self.assertFormError(response.context["form"], None, "Invalid app: Could not read Distribution file")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_package_post(self, post_event):
        package_file = self._build_package(name="Test345")
        self.login("mdm.add_package", "mdm.view_package")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:create_package"),
                                        {"name": name,
                                         "description": "A test package",
                                         "file": package_file},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "mdm/package_detail.html")
        package = response.context["object"]
        self.assertEqual(package.name, name)
        self.assertEqual(package.description, "A test package")
        self.assertEqual(package.product_id, "io.zentral.test345")
        self.assertEqual(package.product_version, "1.0")
        self.assertEqual(package.filename, "Test345.pkg")
        self.assertEqual(package.type, Package.Type.PKG)
        self.assertTrue(package.sha256)
        self.assertGreater(package.size, 0)
        self.assertTrue(package.manifest)
        # event
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(event.payload["action"], "created")
        self.assertEqual(event.payload["object"]["model"], "mdm.package")
        self.assertEqual(event.payload["object"]["pk"], str(package.pk))
        self.assertEqual(event.payload["object"]["new_value"]["pk"], str(package.pk))
        self.assertEqual(event.payload["object"]["new_value"]["name"], name)
        self.assertEqual(event.payload["object"]["new_value"]["product_id"], "io.zentral.test345")
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_package": [str(package.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    @patch("zentral.contrib.mdm.forms.read_package_info")
    def test_create_package_post_ipa(self, mocked_read_package_info):
        mocked_read_package_info.return_value = (
            "Whatever",
            [],
            {"package_sha256": "a" * 64,
             "package_size": 1234,
             "product_id": "io.zentral.ipa",
             "product_version": "2.0",
             "bundles": [],
             "manifest": {"items": []}},
        )
        ipa_upload = BytesIO(b"not really an ipa")
        ipa_upload.name = "something.ipa"
        self.login("mdm.add_package", "mdm.view_package")
        response = self.client.post(reverse("mdm:create_package"),
                                    {"name": "ipa pkg", "description": "", "file": ipa_upload},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/package_detail.html")
        package = response.context["object"]
        self.assertEqual(package.type, Package.Type.IPA)
        self.assertEqual(package.filename, "something.ipa")

    def test_create_package_post_duplicate_sha256(self):
        # build_test_package_file shares cached bytes with force_package so the
        # upload's sha256 matches the existing row.
        existing = force_package(name="first")
        package_file = build_test_package_file()
        package_file.seek(0)
        self.login("mdm.add_package", "mdm.view_package")
        response = self.client.post(reverse("mdm:create_package"),
                                    {"name": "second",
                                     "description": "",
                                     "file": package_file},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/package_form.html")
        self.assertFormError(response.context["form"], "file",
                             "A package with the same SHA256 already exists.")
        # only the original survived
        self.assertEqual(Package.objects.filter(sha256=existing.sha256).count(), 1)

    def test_create_package_post_duplicate_name_allowed(self):
        # Names are not unique: the same name can coexist on multiple packages
        # (e.g. successive versions of the same product). sha256 uniqueness is
        # what prevents true duplicates.
        existing = force_package(name="shared-name")
        package_file = self._build_package(name="Test345")
        self.login("mdm.add_package", "mdm.view_package")
        response = self.client.post(reverse("mdm:create_package"),
                                    {"name": existing.name,
                                     "description": "",
                                     "file": package_file},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/package_detail.html")
        self.assertEqual(Package.objects.filter(name=existing.name).count(), 2)

    # update

    def test_update_package_redirect(self):
        package = force_package()
        self.login_redirect("update_package", package.pk)

    def test_update_package_permission_denied(self):
        package = force_package()
        self.login()
        response = self.client.get(reverse("mdm:update_package", args=(package.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_package_get(self):
        package = force_package()
        self.login("mdm.change_package")
        response = self.client.get(reverse("mdm:update_package", args=(package.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/package_update_form.html")
        # only name and description fields are present
        self.assertContains(response, 'name="name"')
        self.assertContains(response, 'name="description"')
        self.assertNotContains(response, 'name="file"')

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_package_post(self, post_event):
        package = force_package()
        original_product_id = package.product_id
        original_sha256 = package.sha256
        new_name = get_random_string(12)
        self.login("mdm.change_package", "mdm.view_package")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("mdm:update_package", args=(package.pk,)),
                {"name": new_name, "description": "Updated description"},
                follow=True,
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "mdm/package_detail.html")
        package.refresh_from_db()
        self.assertEqual(package.name, new_name)
        self.assertEqual(package.description, "Updated description")
        # analysed fields untouched
        self.assertEqual(package.product_id, original_product_id)
        self.assertEqual(package.sha256, original_sha256)
        # event
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(event.payload["action"], "updated")
        self.assertEqual(event.payload["object"]["new_value"]["name"], new_name)
        self.assertEqual(event.payload["object"]["new_value"]["description"], "Updated description")

    # delete

    def test_delete_package_redirect(self):
        package = force_package()
        self.login_redirect("delete_package", package.pk)

    def test_delete_package_permission_denied(self):
        package = force_package()
        self.login()
        response = self.client.get(reverse("mdm:delete_package", args=(package.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_package_get(self):
        package = force_package()
        self.login("mdm.delete_package")
        response = self.client.get(reverse("mdm:delete_package", args=(package.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/package_confirm_delete.html")
        self.assertContains(response, package.name)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_package_post(self, post_event):
        package = force_package()
        pk = package.pk
        self.login("mdm.delete_package", "mdm.view_package")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:delete_package", args=(pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "mdm/package_list.html")
        self.assertFalse(Package.objects.filter(pk=pk).exists())
        # event
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(event.payload["action"], "deleted")
        self.assertEqual(event.payload["object"]["model"], "mdm.package")
        self.assertEqual(event.payload["object"]["pk"], str(pk))
        self.assertIn("prev_value", event.payload["object"])

    # download

    def test_download_package_redirect(self):
        package = force_package()
        self.login_redirect("download_package", package.pk)

    def test_download_package_permission_denied(self):
        package = force_package()
        self.login()
        response = self.client.get(reverse("mdm:download_package", args=(package.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_download_package(self):
        package = force_package()
        self.login("mdm.view_package")
        response = self.client.get(reverse("mdm:download_package", args=(package.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response["Content-Disposition"],
            f'attachment; filename="{package.filename}"'
        )

    @patch("zentral.contrib.mdm.views.packages.file_storage_has_signed_urls")
    def test_download_package_redirect_to_storage(self, file_storage_has_signed_urls):
        file_storage_has_signed_urls.return_value = True
        package = force_package()
        self.login("mdm.view_package")
        response = self.client.get(reverse("mdm:download_package", args=(package.pk,)))
        self.assertEqual(response.status_code, 302)

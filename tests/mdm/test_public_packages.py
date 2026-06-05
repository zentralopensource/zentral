import plistlib
import uuid
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.declarations.packages import (
    dump_package_file_token,
    dump_package_manifest_token,
    load_package_file_token,
    load_package_manifest_token,
)

from .utils import force_dep_enrollment_session, force_package


class PackagePublicViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()

    # helpers

    def _build_session(self):
        session, _, _ = force_dep_enrollment_session(self.mbu, authenticated=True, completed=True)
        return session

    # token roundtrip

    def test_manifest_token_roundtrip(self):
        package = force_package()
        session = self._build_session()
        target = Target(session.enrolled_device)
        token = dump_package_manifest_token(session, target, package.pk)
        loaded_package, loaded_session, loaded_user = load_package_manifest_token(token)
        self.assertEqual(loaded_package, package)
        self.assertEqual(loaded_session.pk, session.pk)
        self.assertIsNone(loaded_user)

    def test_file_token_roundtrip(self):
        package = force_package()
        session = self._build_session()
        target = Target(session.enrolled_device)
        token = dump_package_file_token(session, target, package.pk)
        loaded_package, loaded_session, loaded_user = load_package_file_token(token)
        self.assertEqual(loaded_package, package)
        self.assertEqual(loaded_session.pk, session.pk)
        self.assertIsNone(loaded_user)

    def test_manifest_token_cannot_be_loaded_as_file_token(self):
        package = force_package()
        session = self._build_session()
        target = Target(session.enrolled_device)
        token = dump_package_manifest_token(session, target, package.pk)
        from zentral.contrib.mdm.declarations.exceptions import TokenSignatureError
        with self.assertRaises(TokenSignatureError):
            load_package_file_token(token)

    def test_file_token_cannot_be_loaded_as_manifest_token(self):
        package = force_package()
        session = self._build_session()
        target = Target(session.enrolled_device)
        token = dump_package_file_token(session, target, package.pk)
        from zentral.contrib.mdm.declarations.exceptions import TokenSignatureError
        with self.assertRaises(TokenSignatureError):
            load_package_manifest_token(token)

    def test_manifest_token_stable_across_calls(self):
        # Two calls with the same inputs must produce the same token, regardless
        # of when they happen. Patching time.time to a far-future value between
        # the two calls would catch any timestamp-mixing signer.
        package = force_package()
        session = self._build_session()
        target = Target(session.enrolled_device)
        t1 = dump_package_manifest_token(session, target, package.pk)
        with patch("time.time", return_value=1e12):
            t2 = dump_package_manifest_token(session, target, package.pk)
        self.assertEqual(t1, t2)

    def test_file_token_stable_across_calls(self):
        package = force_package()
        session = self._build_session()
        target = Target(session.enrolled_device)
        t1 = dump_package_file_token(session, target, package.pk)
        with patch("time.time", return_value=1e12):
            t2 = dump_package_file_token(session, target, package.pk)
        self.assertEqual(t1, t2)

    # manifest view

    def test_package_manifest_view_bad_token(self):
        response = self.client.get(reverse("mdm_public:package_manifest", args=("not-a-token",)))
        self.assertEqual(response.status_code, 400)

    def test_package_manifest_view_missing_package(self):
        session = self._build_session()
        token = dump_package_manifest_token(session, Target(session.enrolled_device), uuid.uuid4())
        with self.assertLogs("zentral.contrib.mdm.public_views.mdm", level="ERROR") as captured:
            response = self.client.get(reverse("mdm_public:package_manifest", args=(token,)))
        self.assertEqual(response.status_code, 404)
        self.assertTrue(any("PackageManifestView" in r and "load_package_manifest_token" in r
                            for r in captured.output))

    def test_package_manifest_view_does_not_mutate_stored_manifest(self):
        package = force_package()
        original_assets_0 = dict(package.manifest["items"][0]["assets"][0])
        session = self._build_session()
        token = dump_package_manifest_token(session, Target(session.enrolled_device), package.pk)
        response = self.client.get(reverse("mdm_public:package_manifest", args=(token,)))
        self.assertEqual(response.status_code, 200)
        # response carries an injected "url"; the stored manifest does not.
        plist_assets_0 = plistlib.loads(response.content)["items"][0]["assets"][0]
        self.assertIn("url", plist_assets_0)
        package.refresh_from_db()
        self.assertNotIn("url", package.manifest["items"][0]["assets"][0])
        self.assertEqual(package.manifest["items"][0]["assets"][0], original_assets_0)

    def test_package_manifest_view_returns_plist(self):
        package = force_package()
        session = self._build_session()
        token = dump_package_manifest_token(session, Target(session.enrolled_device), package.pk)
        response = self.client.get(reverse("mdm_public:package_manifest", args=(token,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/x-plist")
        manifest = plistlib.loads(response.content)
        self.assertIn("items", manifest)
        self.assertEqual(len(manifest["items"]), 1)
        assets = manifest["items"][0]["assets"]
        self.assertEqual(assets[0]["kind"], "software-package")
        # injected URL points at the file endpoint, and its embedded token loads.
        url = assets[0]["url"]
        prefix = "https://"
        self.assertTrue(url.startswith(prefix))
        path = url.split("/", 3)[3]  # strip scheme + host
        path = "/" + path
        file_token = path.rstrip("/").rsplit("/", 2)[-2]
        loaded_package, _, _ = load_package_file_token(file_token)
        self.assertEqual(loaded_package, package)
        # Apple's ManifestURL spec prefers SHA-256 when present; the stored
        # manifest already carries the chunked sha256s, no serve-time injection.
        self.assertIn("sha256s", assets[0])
        self.assertIn("sha256-size", assets[0])
        self.assertNotIn("sha256", assets[0])

    # file view

    def test_package_file_view_bad_token(self):
        response = self.client.get(reverse("mdm_public:package_file", args=("not-a-token",)))
        self.assertEqual(response.status_code, 400)

    def test_package_file_view_missing_package(self):
        session = self._build_session()
        token = dump_package_file_token(session, Target(session.enrolled_device), uuid.uuid4())
        response = self.client.get(reverse("mdm_public:package_file", args=(token,)))
        self.assertEqual(response.status_code, 404)

    def test_package_file_view_returns_file(self):
        package = force_package()
        session = self._build_session()
        token = dump_package_file_token(session, Target(session.enrolled_device), package.pk)
        response = self.client.get(reverse("mdm_public:package_file", args=(token,)))
        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment", response.get("Content-Disposition", ""))
        # streamed bytes match the on-disk file
        self.assertEqual(b"".join(response.streaming_content), package.file.read())

    @patch("zentral.contrib.mdm.public_views.mdm.file_storage_has_signed_urls")
    def test_package_file_view_redirects_when_storage_signs_urls(self, file_storage_has_signed_urls):
        file_storage_has_signed_urls.return_value = True
        package = force_package()
        session = self._build_session()
        token = dump_package_file_token(session, Target(session.enrolled_device), package.pk)
        response = self.client.get(reverse("mdm_public:package_file", args=(token,)))
        self.assertEqual(response.status_code, 302)

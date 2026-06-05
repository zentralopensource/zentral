import json
import uuid
from urllib.parse import urlparse

from accounts.models import User
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from tests.zentral_test_utils.login_case import LoginCase
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.declarations import (
    _find_zentral_ref_package,
    declaration_linkers,
    get_declaration_info,
)
from zentral.contrib.mdm.declarations.declaration import build_declaration
from zentral.contrib.mdm.declarations.packages import (
    dump_package_file_token,
    dump_package_manifest_token,
    load_package_file_token,
    load_package_manifest_token,
)
from zentral.contrib.mdm.models import (
    Artifact,
    ArtifactVersion,
    Channel,
    Declaration,
    Package,
    PackageRef,
    Platform,
)

from .utils import force_dep_enrollment_session, force_enrolled_user, force_package


PACKAGE_DECL_TYPE = "com.apple.configuration.package"


class PackageDeclarationLinkerTestCase(TestCase, LoginCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.user = User.objects.create_user("zoidberg", "zoidberg@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    # LoginCase

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "mdm"

    # helpers

    def _decl_source(self, manifest_url):
        return json.dumps({
            "Identifier": str(uuid.uuid4()),
            "ServerToken": str(uuid.uuid4()),
            "Type": PACKAGE_DECL_TYPE,
            "Payload": {"ManifestURL": manifest_url},
        })

    # Linker: manifest_url_paths

    def test_linker_recognizes_manifest_url_leaf(self):
        linker = declaration_linkers[PACKAGE_DECL_TYPE]
        self.assertIn(("ManifestURL",), linker.manifest_url_paths)

    def test_linker_recognizes_app_managed_manifest_url(self):
        linker = declaration_linkers["com.apple.configuration.app.managed"]
        self.assertIn(("ManifestURL",), linker.manifest_url_paths)

    def test_linker_unrelated_declaration_has_no_manifest_url_paths(self):
        linker = declaration_linkers["com.apple.activation.simple"]
        self.assertEqual(linker.manifest_url_paths, set())

    # iter / substitute

    def test_iter_manifest_url_refs_collects_path(self):
        linker = declaration_linkers[PACKAGE_DECL_TYPE]
        collected = []
        linker.iter_manifest_url_refs(
            {"ManifestURL": "ztl:abc", "InstallBehavior": {"Install": "Required"}},
            lambda path, value: collected.append((path, value)),
        )
        self.assertEqual(collected, [(("ManifestURL",), "ztl:abc")])

    def test_substitute_manifest_urls_replaces_value(self):
        linker = declaration_linkers[PACKAGE_DECL_TYPE]
        result = linker.substitute_manifest_urls(
            {"ManifestURL": "ztl:placeholder", "InstallBehavior": {"Install": "Required"}},
            {("ManifestURL",): "https://example.com/manifest"},
        )
        self.assertEqual(result["ManifestURL"], "https://example.com/manifest")
        self.assertEqual(result["InstallBehavior"], {"Install": "Required"})

    def test_substitute_manifest_urls_walks_lists(self):
        # The recursive walker handles arrays for symmetry with substitute_refs,
        # even though Apple's current schemas never put a ManifestURL inside an
        # array.
        linker = declaration_linkers[PACKAGE_DECL_TYPE]
        result = linker.substitute_manifest_urls(
            {"items": [{"ManifestURL": "ztl:placeholder"}, {"ManifestURL": "ztl:other"}]},
            {("items", "0", "ManifestURL"): "https://a.example", ("items", "1", "ManifestURL"): "https://b.example"},
        )
        self.assertEqual(
            result,
            {"items": [{"ManifestURL": "https://a.example"}, {"ManifestURL": "https://b.example"}]},
        )

    # _find_zentral_ref_package

    def test_find_zentral_ref_package_resolves(self):
        package = force_package()
        found = _find_zentral_ref_package(f"ztl:{package.pk}")
        self.assertEqual(found, package)

    def test_find_zentral_ref_package_unknown(self):
        with self.assertRaisesMessage(ValueError, "Unknown zentral package"):
            _find_zentral_ref_package(f"ztl:{uuid.uuid4()}")

    def test_find_zentral_ref_package_invalid_uuid(self):
        with self.assertRaisesMessage(ValueError, "Unknown zentral package"):
            _find_zentral_ref_package("ztl:not-a-uuid")

    # token dump/load with an enrolled_user

    def test_package_token_with_enrolled_user_roundtrip(self):
        # When the target carries an EnrolledUser, the token embeds eupk and the
        # loader returns the same EnrolledUser. Covers the eupk branch in
        # _dump_token and the matching load_*_token path.
        package = force_package()
        session, _, _ = force_dep_enrollment_session(self.mbu, authenticated=True, completed=True)
        enrolled_user = force_enrolled_user(session.enrolled_device)
        target = Target(session.enrolled_device, enrolled_user)
        manifest_token = dump_package_manifest_token(session, target, package.pk)
        loaded_pkg, loaded_session, loaded_user = load_package_manifest_token(manifest_token)
        self.assertEqual(loaded_pkg, package)
        self.assertEqual(loaded_session.pk, session.pk)
        self.assertEqual(loaded_user, enrolled_user)
        # also exercise the file-token side
        file_token = dump_package_file_token(session, target, package.pk)
        _, _, file_loaded_user = load_package_file_token(file_token)
        self.assertEqual(file_loaded_user, enrolled_user)

    # get_declaration_info: package_refs extraction

    def test_get_declaration_info_package_ref(self):
        package = force_package()
        info = get_declaration_info(
            self._decl_source(f"ztl:{package.pk}"),
            Channel.DEVICE, [Platform.MACOS],
        )
        self.assertEqual(info["package_refs"], {("ManifestURL",): package})
        self.assertEqual(info["refs"], {})

    def test_get_declaration_info_plain_url_is_not_a_package_ref(self):
        info = get_declaration_info(
            self._decl_source("https://example.com/manifest.plist"),
            Channel.DEVICE, [Platform.MACOS],
        )
        self.assertEqual(info["package_refs"], {})
        # plain URL passes through unchanged
        self.assertEqual(info["payload"]["ManifestURL"], "https://example.com/manifest.plist")

    def test_get_declaration_info_unknown_package_raises(self):
        with self.assertRaises(ValueError):
            get_declaration_info(
                self._decl_source(f"ztl:{uuid.uuid4()}"),
                Channel.DEVICE, [Platform.MACOS],
            )

    # build_declaration: substitution

    def _make_declaration_artifact(self, manifest_url_value):
        # Build a Declaration row pointing at a Package via ManifestURL.
        package = force_package() if manifest_url_value.startswith("ztl:placeholder") else None
        if package:
            manifest_url_value = f"ztl:{package.pk}"
        artifact = Artifact.objects.create(
            name=get_random_string(12),
            type=Artifact.Type.CONFIGURATION,
            channel=Channel.DEVICE,
            platforms=[Platform.MACOS],
        )
        artifact_version = ArtifactVersion.objects.create(artifact=artifact, version=1, macos=True)
        decl_payload = {"ManifestURL": manifest_url_value}
        declaration = Declaration.objects.create(
            artifact_version=artifact_version,
            type=PACKAGE_DECL_TYPE,
            identifier=str(uuid.uuid4()),
            server_token=str(uuid.uuid4()),
            payload=decl_payload,
        )
        if package:
            PackageRef.objects.create(declaration=declaration, key=("ManifestURL",), package=package)
        return artifact, artifact_version, declaration, package

    def test_build_declaration_substitutes_manifest_url(self):
        artifact, artifact_version, declaration, package = self._make_declaration_artifact("ztl:placeholder")
        session, _, _ = force_dep_enrollment_session(self.mbu, authenticated=True, completed=True)
        # Make the artifact reachable by the Target.
        # Target.all_installed_or_to_install_serialized iterates Artifacts assigned via
        # blueprints. For this test we patch the iteration to return our artifact directly.
        target = Target(session.enrolled_device)
        from unittest.mock import patch as mock_patch
        d_artifact = {"pk": str(artifact.pk),
                      "type": artifact.type,
                      "reinstall_on_os_update": Artifact.ReinstallOnOSUpdate.NO,
                      "reinstall_interval": 0}
        d_artifact_version = {"pk": str(artifact_version.pk), "version": 1}
        with mock_patch.object(Target, "all_installed_or_to_install_serialized",
                               return_value=[(d_artifact, d_artifact_version, 0)]):
            result = build_declaration(session, target, f"zentral.declaration.{artifact.pk}")
        # ManifestURL has been swapped for a real package_manifest URL
        url = result["Payload"]["ManifestURL"]
        path = urlparse(url).path
        token = path.rstrip("/").rsplit("/", 2)[-2]
        loaded_package, _, _ = load_package_manifest_token(token)
        self.assertEqual(loaded_package, package)

    def test_build_declaration_stable_manifest_url_across_calls(self):
        artifact, artifact_version, declaration, package = self._make_declaration_artifact("ztl:placeholder")
        session, _, _ = force_dep_enrollment_session(self.mbu, authenticated=True, completed=True)
        target = Target(session.enrolled_device)
        from unittest.mock import patch as mock_patch
        d_artifact = {"pk": str(artifact.pk),
                      "type": artifact.type,
                      "reinstall_on_os_update": Artifact.ReinstallOnOSUpdate.NO,
                      "reinstall_interval": 0}
        d_artifact_version = {"pk": str(artifact_version.pk), "version": 1}
        with mock_patch.object(Target, "all_installed_or_to_install_serialized",
                               return_value=[(d_artifact, d_artifact_version, 0)]):
            r1 = build_declaration(session, target, f"zentral.declaration.{artifact.pk}")
            r2 = build_declaration(session, target, f"zentral.declaration.{artifact.pk}")
        self.assertEqual(r1["Payload"]["ManifestURL"], r2["Payload"]["ManifestURL"])

    def test_build_declaration_passes_through_plain_url(self):
        artifact, artifact_version, declaration, _ = self._make_declaration_artifact("https://example.com/m.plist")
        session, _, _ = force_dep_enrollment_session(self.mbu, authenticated=True, completed=True)
        target = Target(session.enrolled_device)
        from unittest.mock import patch as mock_patch
        d_artifact = {"pk": str(artifact.pk),
                      "type": artifact.type,
                      "reinstall_on_os_update": Artifact.ReinstallOnOSUpdate.NO,
                      "reinstall_interval": 0}
        d_artifact_version = {"pk": str(artifact_version.pk), "version": 1}
        with mock_patch.object(Target, "all_installed_or_to_install_serialized",
                               return_value=[(d_artifact, d_artifact_version, 0)]):
            result = build_declaration(session, target, f"zentral.declaration.{artifact.pk}")
        self.assertEqual(result["Payload"]["ManifestURL"], "https://example.com/m.plist")

    # Package deletion guard

    def test_can_be_deleted_blocks_referenced_package(self):
        artifact, _, declaration, package = self._make_declaration_artifact("ztl:placeholder")
        self.assertFalse(package.can_be_deleted())
        self.assertNotIn(package, Package.objects.can_be_deleted())

    def test_can_be_deleted_allows_unreferenced_package(self):
        package = force_package()
        self.assertTrue(package.can_be_deleted())
        self.assertIn(package, Package.objects.can_be_deleted())

    # UI cross-link: ArtifactVersion detail -> Package

    def test_artifact_version_detail_links_to_referenced_package(self):
        artifact, artifact_version, declaration, package = self._make_declaration_artifact("ztl:placeholder")
        self.login("mdm.view_artifactversion", "mdm.view_artifact", "mdm.view_package")
        response = self.client.get(
            reverse("mdm:artifact_version", args=(artifact.pk, artifact_version.pk))
        )
        self.assertEqual(response.status_code, 200)
        # Package reference row is rendered and links to the package detail page,
        # with product_id and product_version visible inline.
        self.assertContains(response, "Package reference")
        self.assertContains(response, reverse("mdm:package", args=(package.pk,)))
        self.assertContains(response, package.name)
        self.assertContains(response, package.product_id)
        self.assertContains(response, package.product_version)

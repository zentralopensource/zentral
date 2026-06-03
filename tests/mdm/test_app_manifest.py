import plistlib
import subprocess
import zipfile
from hashlib import md5, sha256
from io import BytesIO
from unittest.mock import patch

from django.test import SimpleTestCase

from zentral.contrib.mdm.app_manifest import (
    build_manifest_metadata,
    compute_package_hashes,
    read_distribution_info,
    read_ipa_info,
)
from zentral.contrib.mdm.models import Platform


class BuildManifestMetadataTestCase(SimpleTestCase):
    def _pkg_data(self, **overrides):
        pkg_data = {
            "product_id": "io.zentral.test",
            "product_version": "1.0",
            "bundles": [],
        }
        pkg_data.update(overrides)
        return pkg_data

    # happy path

    def test_minimal(self):
        metadata = build_manifest_metadata("Test", self._pkg_data())
        self.assertEqual(
            metadata,
            {"kind": "software",
             "title": "Test",
             "bundle-identifier": "io.zentral.test",
             "bundle-version": "1.0"},
        )

    def test_with_platform_identifier(self):
        metadata = build_manifest_metadata(
            "Test", self._pkg_data(platform_identifier="com.apple.platform.iphoneos"),
        )
        self.assertEqual(
            metadata,
            {"kind": "software",
             "title": "Test",
             "bundle-identifier": "io.zentral.test",
             "bundle-version": "1.0",
             "platform-identifier": "com.apple.platform.iphoneos"},
        )

    # platform-identifier

    def test_platform_identifier_popped_from_pkg_data(self):
        pkg_data = self._pkg_data(platform_identifier="com.apple.platform.iphoneos")
        build_manifest_metadata("Test", pkg_data)
        self.assertNotIn("platform_identifier", pkg_data)

    def test_platform_identifier_omitted_when_missing(self):
        metadata = build_manifest_metadata("Test", self._pkg_data())
        self.assertNotIn("platform-identifier", metadata)

    def test_platform_identifier_omitted_when_empty(self):
        metadata = build_manifest_metadata("Test", self._pkg_data(platform_identifier=""))
        self.assertNotIn("platform-identifier", metadata)

    # metadata.items is marked "removed" in Apple's manifesturl.yaml schema;
    # we never emit it, even when bundles describe sub-payloads.

    def test_metadata_items_never_emitted(self):
        pkg_data = self._pkg_data(bundles=[
            {"id": "io.zentral.test.app", "version_str": "1.0", "version": "1", "path": "/a"},
            {"id": "io.zentral.test.helper", "version_str": "1.1", "version": "2", "path": "/b"},
        ])
        metadata = build_manifest_metadata("Test", pkg_data)
        self.assertNotIn("items", metadata)

    # required-key validation

    def test_empty_title_rejected(self):
        with self.assertRaises(ValueError) as cm:
            build_manifest_metadata("", self._pkg_data())
        self.assertIn("title", str(cm.exception))

    def test_empty_product_id_rejected(self):
        with self.assertRaises(ValueError) as cm:
            build_manifest_metadata("Test", self._pkg_data(product_id=""))
        self.assertIn("bundle-identifier", str(cm.exception))

    def test_empty_product_version_rejected(self):
        with self.assertRaises(ValueError) as cm:
            build_manifest_metadata("Test", self._pkg_data(product_version=""))
        self.assertIn("bundle-version", str(cm.exception))

    def test_multiple_missing_keys_all_reported(self):
        with self.assertRaises(ValueError) as cm:
            build_manifest_metadata("", self._pkg_data(product_id="", product_version=""))
        msg = str(cm.exception)
        for k in ("title", "bundle-identifier", "bundle-version"):
            self.assertIn(k, msg)

    def test_non_string_title_rejected(self):
        with self.assertRaises(ValueError):
            build_manifest_metadata(None, self._pkg_data())


class ReadIPAInfoTestCase(SimpleTestCase):
    def _build_ipa(self, info_plist, plist_path="Payload/App.app/Info.plist"):
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(plist_path, plistlib.dumps(info_plist))
        buf.seek(0)
        return buf

    def _read(self, info_plist):
        return read_ipa_info(self._build_ipa(info_plist))

    def _default_info_plist(self, **overrides):
        info_plist = {
            "CFBundleExecutable": "TestApp",
            "CFBundleIdentifier": "com.example.test",
            "CFBundleShortVersionString": "1.0",
            "CFBundleVersion": "1",
            "DTPlatformName": "iphoneos",
            "UIDeviceFamily": [1],
        }
        info_plist.update(overrides)
        return info_plist

    def test_emits_platform_identifier_from_dt_platform_name(self):
        name, platforms, pkg_data = self._read(self._default_info_plist())
        self.assertEqual(name, "TestApp")
        self.assertEqual(pkg_data["product_id"], "com.example.test")
        self.assertEqual(pkg_data["product_version"], "1.0")
        self.assertEqual(pkg_data["platform_identifier"], "com.apple.platform.iphoneos")
        self.assertEqual(
            pkg_data["bundles"],
            [{"id": "com.example.test", "version_str": "1.0", "version": "1"}],
        )
        self.assertEqual(platforms, [Platform.IOS])

    def test_no_metadata_key_in_pkg_data(self):
        # Before the refactor, read_ipa_info populated pkg_data["metadata"]; that
        # block now lives in build_manifest_metadata. Guard against regression.
        _, _, pkg_data = self._read(self._default_info_plist())
        self.assertNotIn("metadata", pkg_data)

    def test_platform_identifier_reflects_dt_platform_name_verbatim(self):
        _, _, pkg_data = self._read(self._default_info_plist(DTPlatformName="appletvos"))
        self.assertEqual(pkg_data["platform_identifier"], "com.apple.platform.appletvos")

    def test_device_family_scalar_accepted(self):
        _, platforms, _ = self._read(self._default_info_plist(UIDeviceFamily=2))
        self.assertEqual(platforms, [Platform.IPADOS])

    def test_device_family_multiple(self):
        _, platforms, _ = self._read(self._default_info_plist(UIDeviceFamily=[1, 2, 3]))
        self.assertEqual(platforms, [Platform.IOS, Platform.IPADOS, Platform.TVOS])

    def test_missing_info_plist_key_raises(self):
        info_plist = self._default_info_plist()
        del info_plist["DTPlatformName"]
        with self.assertRaises(ValueError) as cm:
            self._read(info_plist)
        self.assertIn("DTPlatformName", str(cm.exception))

    def test_missing_ui_device_family_raises(self):
        info_plist = self._default_info_plist()
        del info_plist["UIDeviceFamily"]
        with self.assertRaises(ValueError) as cm:
            self._read(info_plist)
        self.assertIn("UIDeviceFamily", str(cm.exception))

    def test_bad_zip_raises(self):
        with self.assertRaises(ValueError) as cm:
            read_ipa_info(BytesIO(b"not a zip"))
        self.assertIn("IPA", str(cm.exception))

    def test_missing_info_plist_in_zip_raises(self):
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("Payload/App.app/empty.txt", b"")
        buf.seek(0)
        with self.assertRaises(ValueError) as cm:
            read_ipa_info(buf)
        self.assertIn("Info.plist", str(cm.exception))

    def test_unloadable_info_plist_raises(self):
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("Payload/App.app/Info.plist", b"not a plist")
        buf.seek(0)
        with self.assertRaises(ValueError) as cm:
            read_ipa_info(buf)
        self.assertIn("Info.plist", str(cm.exception))


class ComputePackageHashesTestCase(SimpleTestCase):
    def test_single_chunk_file(self):
        payload = b"hello"
        chunk_size, md5s, sha256s, package_size, file_sha256 = compute_package_hashes(BytesIO(payload))
        self.assertEqual(chunk_size, len(payload))
        self.assertEqual(md5s, [md5(payload).hexdigest()])
        self.assertEqual(sha256s, [sha256(payload).hexdigest()])
        self.assertEqual(package_size, len(payload))
        self.assertIsNone(file_sha256)

    def test_multi_chunk_file_md5s_and_sha256s_in_lockstep(self):
        chunk_size = 64 * 1024
        payload = b"A" * (3 * chunk_size)
        returned_chunk_size, md5s, sha256s, package_size, _ = compute_package_hashes(
            BytesIO(payload), chunk_size=chunk_size,
        )
        self.assertEqual(returned_chunk_size, chunk_size)
        self.assertEqual(package_size, len(payload))
        self.assertEqual(len(md5s), 3)
        self.assertEqual(len(sha256s), 3)
        expected_md5 = md5(b"A" * chunk_size).hexdigest()
        expected_sha256 = sha256(b"A" * chunk_size).hexdigest()
        self.assertEqual(md5s, [expected_md5] * 3)
        self.assertEqual(sha256s, [expected_sha256] * 3)

    def test_multi_chunk_file_partial_final_chunk(self):
        chunk_size = 64 * 1024
        payload = b"A" * (2 * chunk_size) + b"B" * 10
        returned_chunk_size, md5s, sha256s, package_size, _ = compute_package_hashes(
            BytesIO(payload), chunk_size=chunk_size,
        )
        self.assertEqual(returned_chunk_size, chunk_size)
        self.assertEqual(package_size, len(payload))
        self.assertEqual(len(md5s), 3)
        self.assertEqual(len(sha256s), 3)
        self.assertEqual(md5s[2], md5(b"B" * 10).hexdigest())
        self.assertEqual(sha256s[2], sha256(b"B" * 10).hexdigest())

    def test_compute_sha256_returns_whole_file_digest(self):
        payload = b"hello world"
        _, _, _, _, file_sha256 = compute_package_hashes(BytesIO(payload), compute_sha256=True)
        self.assertEqual(file_sha256, sha256(payload).hexdigest())

    def test_compute_sha256_false_returns_none(self):
        _, _, _, _, file_sha256 = compute_package_hashes(BytesIO(b"x"))
        self.assertIsNone(file_sha256)

    def test_chunk_size_floored_to_file_chunk_size(self):
        # chunk_size is rounded down to a multiple of file_chunk_size (64KB).
        chunk_size = 64 * 1024
        returned_chunk_size, md5s, _, _, _ = compute_package_hashes(
            BytesIO(b"A" * (2 * chunk_size)), chunk_size=chunk_size + 10,
        )
        self.assertEqual(returned_chunk_size, chunk_size)
        self.assertEqual(len(md5s), 2)


class ReadDistributionInfoTestCase(SimpleTestCase):
    """Direct unit tests for read_distribution_info.

    build_dummy_package doesn't produce a Distribution with <bundle> elements,
    so we mock subprocess.run (the xar extraction) to inject the XML directly.
    """

    def _read(self, xml_bytes):
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=xml_bytes, stderr=b"")
        with patch("zentral.contrib.mdm.app_manifest.subprocess.run", return_value=completed):
            return read_distribution_info("/dev/null")

    def test_bundles_populated_from_bundle_elements(self):
        xml = (b'<?xml version="1.0"?>'
               b'<installer-script>'
               b'<product id="io.zentral.test" version="1.0"/>'
               b'<title>Test</title>'
               b'<pkg-ref id="io.zentral.test.app">'
               b'<bundle CFBundleShortVersionString="1.0"'
               b'        CFBundleVersion="1"'
               b'        id="io.zentral.test.app"'
               b'        path="Applications/Test.app"/>'
               b'<bundle CFBundleShortVersionString="1.1"'
               b'        CFBundleVersion="2"'
               b'        id="io.zentral.test.helper"'
               b'        path="Applications/Test.app/Contents/Helpers/Helper.app"/>'
               b'</pkg-ref>'
               b'</installer-script>')
        name, platforms, pkg_data = self._read(xml)
        self.assertEqual(name, "Test")
        self.assertEqual(platforms, [Platform.MACOS])
        self.assertEqual(pkg_data["product_id"], "io.zentral.test")
        self.assertEqual(pkg_data["product_version"], "1.0")
        self.assertEqual(
            pkg_data["bundles"],
            [{"version_str": "1.0", "version": "1",
              "id": "io.zentral.test.app", "path": "Applications/Test.app"},
             {"version_str": "1.1", "version": "2",
              "id": "io.zentral.test.helper",
              "path": "Applications/Test.app/Contents/Helpers/Helper.app"}],
        )

    def test_bundle_with_missing_attr_skipped(self):
        # A <bundle> missing one of the required attributes is logged and skipped,
        # while well-formed siblings still make it into pkg_data["bundles"].
        xml = (b'<?xml version="1.0"?>'
               b'<installer-script>'
               b'<product id="io.zentral.test" version="1.0"/>'
               b'<bundle CFBundleShortVersionString="1.0"'
               b'        id="io.zentral.test.broken"'
               b'        path="x"/>'  # missing CFBundleVersion
               b'<bundle CFBundleShortVersionString="1.0"'
               b'        CFBundleVersion="1"'
               b'        id="io.zentral.test.app"'
               b'        path="Applications/Test.app"/>'
               b'</installer-script>')
        _, _, pkg_data = self._read(xml)
        self.assertEqual(len(pkg_data["bundles"]), 1)
        self.assertEqual(pkg_data["bundles"][0]["id"], "io.zentral.test.app")

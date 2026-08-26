import os
import plistlib
import shutil
import stat
import tempfile
from unittest.mock import patch
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import SimpleTestCase
from zentral.utils.osx_package import (BasePackageBuilder, get_package_builders,
                                       get_standalone_package_builders, get_tls_hostname)
from .packages import DummyPackageBuilder, build_dummy_package


class OSXPackageBuilderTestCase(SimpleTestCase):
    def _dummy_builder(self, name="test123", version="1.0", product_archive_title=None):
        builder = DummyPackageBuilder(name, version, product_archive_title)
        self.addCleanup(builder.cleanup)
        self.addCleanup(shutil.rmtree, builder.tempdir, True)
        return builder

    def _component_package_dir(self, identifier, version, bundles=()):
        package_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, package_dir, True)
        bundle_elms = "".join(
            '<bundle CFBundleShortVersionString="{}" CFBundleVersion="{}" id="{}" path="{}"/>'.format(*b)
            for b in bundles
        )
        with open(os.path.join(package_dir, "PackageInfo"), "w") as f:
            f.write('<?xml version="1.0" encoding="utf-8" standalone="no"?>'
                    f'<pkg-info format-version="2" identifier="{identifier}" version="{version}"'
                    ' install-location="/" auth="root">'
                    '<payload numberOfFiles="1" installKBytes="1"/>'
                    f'{bundle_elms}'
                    '</pkg-info>')
        return package_dir

    def _package_file(self, **kwargs):
        fd, path = tempfile.mkstemp(suffix=".pkg")
        self.addCleanup(os.unlink, path)
        with os.fdopen(fd, "wb") as f:
            f.write(build_dummy_package(**kwargs))
        return path

    # signature

    def test_get_signature_size(self):
        builder = BasePackageBuilder()
        self.addCleanup(builder._clean)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_path = os.path.join(builder.tempdir, "signing.key")
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        # a RSA-2048 signature is the size of the modulus, 256 bytes
        self.assertEqual(builder._get_signature_size(key_path), 256)

    def test_sign_pkg(self):
        builder = BasePackageBuilder()
        self.addCleanup(builder._clean)
        with patch("zentral.utils.osx_package.check_output", return_value=b"0" * 256), \
             patch("zentral.utils.osx_package.check_call") as check_call:
            builder._sign_pkg("/fomo/yolo.pkg", "/fomo/cert.pem", "/fomo/key.pem")
        add_cert_args, sign_args, inject_args = (c.args[0] for c in check_call.call_args_list)
        self.assertEqual(add_cert_args[:2], ["/usr/local/bin/xar", "--sign"])
        self.assertEqual(add_cert_args[add_cert_args.index("--sig-size") + 1], "256")
        self.assertEqual(add_cert_args[add_cert_args.index("--cert-loc") + 1], "/fomo/cert.pem")
        self.assertEqual(sign_args[:3], ["/usr/bin/openssl", "rsautl", "-sign"])
        self.assertEqual(sign_args[sign_args.index("-inkey") + 1], "/fomo/key.pem")
        self.assertEqual(inject_args[:2], ["/usr/local/bin/xar", "--inject-sig"])
        self.assertEqual(inject_args[inject_args.index("-f") + 1], "/fomo/yolo.pkg")

    def test_no_developer_id_no_signature(self):
        builder = BasePackageBuilder()
        self.addCleanup(builder._clean)
        with patch("zentral.utils.osx_package.settings", {"api": {}}):
            self.assertEqual(builder._get_certificate_and_private_key(), (None, None))

    def test_developer_id_missing_attributes(self):
        builder = BasePackageBuilder()
        self.addCleanup(builder._clean)
        with patch("zentral.utils.osx_package.settings", {"api": {"developer_id": {}}}), \
             self.assertLogs("zentral.utils.osx_package", level="ERROR") as cm:
            self.assertEqual(builder._get_certificate_and_private_key(), (None, None))
        self.assertEqual(cm.output,
                         ["ERROR:zentral.utils.osx_package:Missing certificate in developer id configuration",
                          "ERROR:zentral.utils.osx_package:Missing private_key in developer id configuration"])

    def test_developer_id_missing_files(self):
        builder = BasePackageBuilder()
        self.addCleanup(builder._clean)
        developer_id = {"certificate": "/fomo/yolo.pem", "private_key": "/fomo/yolo.key"}
        with patch("zentral.utils.osx_package.settings", {"api": {"developer_id": developer_id}}), \
             self.assertLogs("zentral.utils.osx_package", level="ERROR") as cm:
            self.assertEqual(builder._get_certificate_and_private_key(), (None, None))
        self.assertEqual(cm.output, ["ERROR:zentral.utils.osx_package:File /fomo/yolo.pem does not exist",
                                     "ERROR:zentral.utils.osx_package:File /fomo/yolo.key does not exist"])

    def test_developer_id(self):
        builder = BasePackageBuilder()
        self.addCleanup(builder._clean)
        certificate = self._package_file()
        private_key = self._package_file()
        developer_id = {"certificate": certificate, "private_key": private_key}
        with patch("zentral.utils.osx_package.settings", {"api": {"developer_id": developer_id}}):
            self.assertEqual(builder._get_certificate_and_private_key(), (certificate, private_key))

    def test_build_pkg_signs_the_package(self):
        with patch.object(BasePackageBuilder, "_get_certificate_and_private_key",
                          return_value=("/fomo/cert.pem", "/fomo/key.pem")), \
             patch.object(BasePackageBuilder, "_sign_pkg") as sign_pkg:
            self.assertTrue(build_dummy_package().startswith(b"xar!"))
        sign_pkg.assert_called_once()
        self.assertEqual(sign_pkg.call_args.args[1:], ("/fomo/cert.pem", "/fomo/key.pem"))

    # builder defaults

    def test_builder_defaults(self):
        builder = self._dummy_builder()
        self.assertIsNone(builder.get_extra_installcheck_script())
        self.assertEqual(builder.get_extra_packages(), [])
        self.assertIsNone(builder.get_etag())
        self.assertIsNone(builder.get_last_modified_dt())

    # tls hostname

    def test_get_tls_hostname(self):
        api = {"fqdn": "zentral.example.com", "fqdn_mtls": "zentral-mtls.example.com"}
        with patch("zentral.utils.osx_package.settings", {"api": api}):
            self.assertEqual(get_tls_hostname(), "zentral.example.com")
            self.assertEqual(get_tls_hostname(for_client_cert_auth=True), "zentral-mtls.example.com")

    # package builders

    def test_get_standalone_package_builders(self):
        osquery_builder = "zentral.contrib.osquery.osx_package.builder.OsqueryZentralEnrollPkgBuilder"
        munki_builder = "zentral.contrib.munki.osx_package.builder.MunkiZentralEnrollPkgBuilder"
        self.assertIn(osquery_builder, get_package_builders())
        self.assertIn(munki_builder, get_package_builders())
        # only the osquery enrollment package can be downloaded on its own
        self.assertIn(osquery_builder, get_standalone_package_builders())
        self.assertNotIn(munki_builder, get_standalone_package_builders())

    # payload helpers

    def test_set_plist_keys(self):
        builder = self._dummy_builder()
        plist_path = os.path.join(builder.tempdir, "test.plist")
        with open(plist_path, "wb") as f:
            plistlib.dump({"un": 1}, f)
        builder.set_plist_keys(plist_path, [])
        builder.set_plist_keys(plist_path, [("un", 11), ("deux", 2)])
        with open(plist_path, "rb") as f:
            self.assertEqual(plistlib.load(f), {"un": 11, "deux": 2})

    def test_append_to_plist_key(self):
        builder = self._dummy_builder()
        plist_path = os.path.join(builder.tempdir, "test.plist")
        with open(plist_path, "wb") as f:
            plistlib.dump({"un": ["yolo"]}, f)
        builder.append_to_plist_key(plist_path, "un", [])
        builder.append_to_plist_key(plist_path, "un", ["fomo"])
        builder.append_to_plist_key(plist_path, "deux", ["haha"])
        with open(plist_path, "rb") as f:
            self.assertEqual(plistlib.load(f), {"un": ["yolo", "fomo"], "deux": ["haha"]})

    def test_create_file_with_content_string(self):
        builder = self._dummy_builder()
        builder.create_file_with_content_string("usr/local/zentral/yolo/fomo.txt", "yolo")
        builder.create_file_with_content_string("usr/local/zentral/yolo/fomo.sh", "#!/bin/bash", executable=True)
        text_path = builder.get_root_path("usr/local/zentral/yolo/fomo.txt")
        script_path = builder.get_root_path("usr/local/zentral/yolo/fomo.sh")
        with open(text_path) as f:
            self.assertEqual(f.read(), "yolo")
        self.assertFalse(os.stat(text_path).st_mode & stat.S_IXUSR)
        self.assertTrue(os.stat(script_path).st_mode & stat.S_IXUSR)

    # product archive

    def test_product_archive_with_a_component_package_dir(self):
        builder = self._dummy_builder(product_archive_title="Test")
        extra_package = self._component_package_dir(
            "io.zentral.extra", "2.0",
            bundles=(("1.2", "12", "io.zentral.extra.app", "./Applications/Extra.app"),)
        )
        with patch.object(DummyPackageBuilder, "get_extra_packages", return_value=[extra_package]):
            _, pkg_refs, content = builder.build()
        self.assertEqual(pkg_refs, [{"id": "io.zentral.extra", "version": "2.0"},
                                    {"id": "io.zentral.test123", "version": "1.0"}])
        self.assertTrue(content.startswith(b"xar!"))

    def test_product_archive_with_a_component_package_file(self):
        builder = self._dummy_builder(product_archive_title="Test")
        extra_package = self._package_file(name="extra123", version="2.0")
        with patch.object(DummyPackageBuilder, "get_extra_packages", return_value=[extra_package]):
            _, pkg_refs, content = builder.build()
        self.assertEqual(pkg_refs, [{"id": "io.zentral.extra123", "version": "2.0"},
                                    {"id": "io.zentral.test123", "version": "1.0"}])
        self.assertTrue(content.startswith(b"xar!"))

    def test_product_archive_with_a_product_archive_file(self):
        builder = self._dummy_builder(product_archive_title="Test")
        # the packages of an extra product archive are added one by one
        extra_package = self._package_file(name="extra123", version="2.0", product_archive_title="Extra")
        with patch.object(DummyPackageBuilder, "get_extra_packages", return_value=[extra_package]):
            _, pkg_refs, content = builder.build()
        self.assertEqual(pkg_refs, [{"id": "io.zentral.extra123", "version": "2.0"},
                                    {"id": "io.zentral.test123", "version": "1.0"}])
        self.assertTrue(content.startswith(b"xar!"))

import copy
import plistlib
import uuid
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.monolith.models import (Catalog, Enrollment,
                                             Manifest, ManifestCatalog, ManifestSubManifest,
                                             PkgInfo, PkgInfoName,
                                             SubManifest, SubManifestPkgInfo)


pkginfo_src = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>name</key>
    <string>ServerAdministrationSoftware</string>
    <key>version</key>
    <string>10.5.5</string>
    <key>description</key>
    <string>Administration tools for OS X Server</string>
    <key>display_name</key>
    <string>Server Administration Software</string>
    <key>installs</key>
    <array>
        <dict>
            <key>type</key>
            <string>application</string>
            <key>path</key>
            <string>/Applications/Server/Server Admin.app</string>
            <key>CFBundleIdentifier</key>
            <string>com.apple.ServerAdmin</string>
            <key>CFBundleName</key>
            <string>Server Admin</string>
            <key>CFBundleShortVersionString</key>
            <string>10.5.3</string>
        </dict>
    </array>
    <key>receipts</key>
    <array>
        <dict>
            <key>packageid</key>
            <string>com.apple.pkg.ServerAdminTools</string>
            <key>version</key>
            <string>10.5.3.0</string>
        </dict>
    </array>
    <key>minimum_os_version</key>
    <string>10.5.0</string>
    <key>installer_item_location</key>
    <string>apps/ServerAdminToold1055.dmg</string>
    <key>uninstallable</key>
    <true/>
    <key>uninstall_method</key>
    <string>removepackages</string>
</dict>
</plist>
"""


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.dummy.DummyCache"}})
class MonolithAPIViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # mbu
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
        cls.mbu.create_enrollment_business_unit()
        # manifest
        cls.manifest = Manifest.objects.create(meta_business_unit=cls.mbu, name=get_random_string())
        # pkginfos
        cls.pkginfo_data = plistlib.loads(pkginfo_src.encode("utf-8"))
        # enrollment
        cls.enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=cls.mbu)
        cls.enrollment = Enrollment.objects.create(secret=cls.enrollment_secret, manifest=cls.manifest)

    # utility methods

    def _make_munki_request(self, url, serial_number=None, authenticated=True):
        kwargs = {
            "HTTP_X_ZENTRAL_SERIAL_NUMBER": serial_number or get_random_string(),
            "HTTP_X_ZENTRAL_UUID": str(uuid.uuid4()),
        }
        if authenticated:
            kwargs["HTTP_AUTHORIZATION"] = f"Bearer {self.enrollment.secret.secret}"
        return self.client.get(url, **kwargs)

    def _force_pkg_info(self, name=None, version=None, shard=None, catalog=None, sub_manifest=None):
        if catalog is None:
            catalog = Catalog.objects.create(name=get_random_string())
        ManifestCatalog.objects.create(manifest=self.manifest, catalog=catalog)
        if name is None:
            name = get_random_string()
        if version is None:
            version = "1.2.3"
        data = copy.deepcopy(self.pkginfo_data)
        data["name"] = name
        data["version"] = version
        data["installs"][0]["CFBundleShortVersionString"] = version
        data["receipts"][0]["version"] = version
        if shard:
            data["zentral_monolith_shard"] = shard
        pkg_info_name, _ = PkgInfoName.objects.get_or_create(name=name)
        pkg_info = PkgInfo.objects.create(
            name=pkg_info_name,
            version=version,
            data=data
        )
        pkg_info.catalogs.set([catalog])
        if sub_manifest is None:
            sub_manifest, _ = SubManifest.objects.get_or_create(name=get_random_string())
        SubManifestPkgInfo.objects.get_or_create(
            sub_manifest=sub_manifest,
            pkg_info_name=pkg_info_name,
            defaults={"key": "managed_installs"}
        )
        ManifestSubManifest.objects.get_or_create(
            manifest=self.manifest,
            sub_manifest=sub_manifest
        )
        return pkg_info, catalog, sub_manifest

    # catalogs

    def test_get_catalog(self):
        pkg_info, catalog, _ = self._force_pkg_info()
        response = self._make_munki_request(
            reverse("monolith:repository_catalog", args=(self.manifest.get_catalog_munki_name(),))
        )
        self.assertEqual(response.status_code, 200)
        catalog = plistlib.loads(response.content)
        self.assertEqual(len(catalog), 1)
        cat_pkg_info = catalog[0]
        self.assertEqual(cat_pkg_info["name"], pkg_info.name.name)
        self.assertEqual(cat_pkg_info["version"], pkg_info.version)

    def test_get_catalog_two_pkg_info_no_shards(self):
        pkg_info1, catalog, sub_manifest = self._force_pkg_info()
        pkg_info2, _, _ = self._force_pkg_info(
            name=pkg_info1.name.name,
            version="1.2.4",
            catalog=catalog,
            sub_manifest=sub_manifest
        )
        response = self._make_munki_request(
            reverse("monolith:repository_catalog", args=(self.manifest.get_catalog_munki_name(),))
        )
        self.assertEqual(response.status_code, 200)
        catalog = plistlib.loads(response.content)
        self.assertEqual(len(catalog), 2)

    def test_get_catalog_two_pkg_info_one_shard_filtered_out(self):
        pkg_info1, catalog, sub_manifest = self._force_pkg_info(name="ceci_n_est_pas_un_nom", version="1.2.3")
        pkg_info2, _, _ = self._force_pkg_info(
            name=pkg_info1.name.name,
            version="1.2.4",
            catalog=catalog,
            sub_manifest=sub_manifest,
            shard=50,  # with NAME + VERSION + SN → 59, no included
        )
        response = self._make_munki_request(
            reverse("monolith:repository_catalog", args=(self.manifest.get_catalog_munki_name(),)),
            serial_number="12345678"
        )
        self.assertEqual(response.status_code, 200)
        catalog = plistlib.loads(response.content)
        self.assertEqual(len(catalog), 1)
        self.assertTrue(all(p.get("zentral_monolith_shard") is None for p in catalog))
        self.assertEqual(catalog[0]["version"], "1.2.3")

    def test_get_catalog_two_pkg_info_one_shard_included(self):
        pkg_info1, catalog, sub_manifest = self._force_pkg_info(name="ceci_n_est_pas_un_nom", version="1.2.3")
        pkg_info2, _, _ = self._force_pkg_info(
            name=pkg_info1.name.name,
            version="1.2.4",
            catalog=catalog,
            sub_manifest=sub_manifest,
            shard=60,  # with NAME + VERSION + SN → 59, included
        )
        response = self._make_munki_request(
            reverse("monolith:repository_catalog", args=(self.manifest.get_catalog_munki_name(),)),
            serial_number="12345678"
        )
        self.assertEqual(response.status_code, 200)
        catalog = plistlib.loads(response.content)
        self.assertEqual(len(catalog), 2)

    def test_get_catalog_two_pkg_info_one_out_of_bounds_shard_included(self):
        pkg_info1, catalog, sub_manifest = self._force_pkg_info(name="ceci_n_est_pas_un_nom", version="1.2.3")
        pkg_info2, _, _ = self._force_pkg_info(
            name=pkg_info1.name.name,
            version="1.2.4",
            catalog=catalog,
            sub_manifest=sub_manifest,
            shard=-17,  # out of bounds, included
        )
        response = self._make_munki_request(
            reverse("monolith:repository_catalog", args=(self.manifest.get_catalog_munki_name(),)),
            serial_number="12345678"
        )
        self.assertEqual(response.status_code, 200)
        catalog = plistlib.loads(response.content)
        self.assertEqual(len(catalog), 2)

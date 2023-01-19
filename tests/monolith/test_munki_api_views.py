import copy
import plistlib
import uuid
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import EnrollmentSecret, MachineTag, MetaBusinessUnit, Tag
from zentral.contrib.monolith.models import (Catalog, Enrollment,
                                             Manifest, ManifestCatalog, ManifestSubManifest,
                                             PkgInfo, PkgInfoName,
                                             SubManifest, SubManifestAttachment, SubManifestPkgInfo)


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
        cls.manifest = Manifest.objects.create(meta_business_unit=cls.mbu, name=get_random_string(12))
        # pkginfos
        cls.pkginfo_data = plistlib.loads(pkginfo_src.encode("utf-8"))
        # enrollment
        cls.enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=cls.mbu)
        cls.enrollment = Enrollment.objects.create(secret=cls.enrollment_secret, manifest=cls.manifest)

    # utility methods

    def _make_munki_request(self, url, serial_number=None, authenticated=True, tags=None):
        if not serial_number:
            serial_number = get_random_string(12)
        if tags:
            MachineTag.objects.bulk_create([
                MachineTag(serial_number=serial_number, tag=tag)
                for tag, _ in (
                    Tag.objects.get_or_create(name=tag_name)
                    for tag_name in tags
                )
            ])
        kwargs = {
            "HTTP_X_ZENTRAL_SERIAL_NUMBER": serial_number,
            "HTTP_X_ZENTRAL_UUID": str(uuid.uuid4()),
        }
        if authenticated:
            kwargs["HTTP_AUTHORIZATION"] = f"Bearer {self.enrollment.secret.secret}"
        return self.client.get(url, **kwargs)

    def _force_smo(
        self,
        name=None,
        version=None,
        catalog=None,
        sub_manifest=None,
        sub_manifest_key=None,
        zentral_monolith=None,
        smo_class=SubManifestPkgInfo,
        smo_options=None
    ):
        if catalog is None:
            catalog = Catalog.objects.create(name=get_random_string(12))
        ManifestCatalog.objects.create(manifest=self.manifest, catalog=catalog)
        if sub_manifest is None:
            sub_manifest, _ = SubManifest.objects.get_or_create(name=get_random_string(12))
        ManifestSubManifest.objects.get_or_create(
            manifest=self.manifest,
            sub_manifest=sub_manifest
        )
        if name is None:
            name = get_random_string(12)
        if smo_options is None:
            smo_options = {}
        pkg_info = None
        if smo_class == SubManifestPkgInfo:
            if version is None:
                version = "1.2.3"
            data = copy.deepcopy(self.pkginfo_data)
            data["name"] = name
            data["version"] = version
            data["installs"][0]["CFBundleShortVersionString"] = version
            data["receipts"][0]["version"] = version
            if zentral_monolith:
                data["zentral_monolith"] = zentral_monolith
            pkg_info_name, _ = PkgInfoName.objects.get_or_create(name=name)
            pkg_info = PkgInfo.objects.create(
                name=pkg_info_name,
                version=version,
                data=data
            )
            pkg_info.catalogs.set([catalog])
            SubManifestPkgInfo.objects.get_or_create(
                sub_manifest=sub_manifest,
                pkg_info_name=pkg_info_name,
                defaults={"key": sub_manifest_key or "managed_installs",
                          "options": smo_options}
            )
        else:
            if version is None:
                version = 1
            data = {
                'display_name': name,
                'description': "description of the script",
                'autoremove': False,
                'unattended_install': True,
                'installer_type': 'nopkg',
                'uninstallable': True,
                'unattended_uninstall': True,
                'minimum_munki_version': '2.2',
                'minimum_os_version': '10.6.0',  # TODO: HARDCODED !!!
                'installcheck_script': "#!/bin/bash\ntrue",
                'postinstall_script': "#!/bin/bash\ntrue",
            }
            SubManifestAttachment.objects.get_or_create(
                sub_manifest=sub_manifest,
                type="script",
                name=name,
                version=version,
                pkg_info=data,
                defaults={"key": sub_manifest_key or "managed_installs"}
            )
        return pkg_info, catalog, sub_manifest

    # catalogs

    def test_get_catalog(self):
        pkg_info, catalog, _ = self._force_smo()
        response = self._make_munki_request(
            reverse("monolith:repository_catalog", args=(self.manifest.get_catalog_munki_name(),))
        )
        self.assertEqual(response.status_code, 200)
        catalog = plistlib.loads(response.content)
        self.assertEqual(len(catalog), 1)
        cat_pkg_info = catalog[0]
        self.assertEqual(cat_pkg_info["name"], pkg_info.name.name)
        self.assertEqual(cat_pkg_info["version"], pkg_info.version)

    def test_get_catalog_two_pkgsinfo_no_shards(self):
        pkg_info1, catalog, sub_manifest = self._force_smo()
        pkg_info2, _, _ = self._force_smo(
            name=pkg_info1.name.name,
            version="1.2.4",
            catalog=catalog,
            sub_manifest=sub_manifest
        )
        response = self._make_munki_request(
            reverse("monolith:repository_catalog", args=(self.manifest.get_catalog_munki_name(),)),
            tags=[get_random_string(12) for _ in range(2)]
        )
        self.assertEqual(response.status_code, 200)
        catalog = plistlib.loads(response.content)
        self.assertEqual(len(catalog), 2)

    def test_get_catalog_two_pkgsinfo_default_shard_filtered_out(self):
        pkg_info1, catalog, sub_manifest = self._force_smo(name="ceci_n_est_pas_un_nom", version="1.2.3")
        pkg_info2, _, _ = self._force_smo(
            name=pkg_info1.name.name,
            version="1.2.4",
            catalog=catalog,
            sub_manifest=sub_manifest,
            zentral_monolith={
                "excluded_tags": ["EXCL1", "EXCL2"],
                "shards": {"default": 50,  # with NAME + VERSION + SN → 59, no included
                           "tags": {"UN": 100, "DEUX": 100}}  # ignored
            }
        )
        response = self._make_munki_request(
            reverse("monolith:repository_catalog", args=(self.manifest.get_catalog_munki_name(),)),
            serial_number="12345678",
            tags=[get_random_string(12) for _ in range(2)]
        )
        self.assertEqual(response.status_code, 200)
        catalog = plistlib.loads(response.content)
        self.assertEqual(len(catalog), 1)
        self.assertTrue(all(p.get("zentral_monolith") is None for p in catalog))
        self.assertEqual(catalog[0]["version"], "1.2.3")

    def test_get_catalog_two_pkgsinfo_default_shard_included(self):
        pkg_info1, catalog, sub_manifest = self._force_smo(name="ceci_n_est_pas_un_nom", version="1.2.3")
        pkg_info2, _, _ = self._force_smo(
            name=pkg_info1.name.name,
            version="1.2.4",
            catalog=catalog,
            sub_manifest=sub_manifest,
            zentral_monolith={
                "excluded_tags": ["EXCL1", "EXCL2"],
                "shards": {"default": 60,  # with NAME + VERSION + SN → 59, included
                           "tags": {"UN": 0, "DEUX": 0}}  # ignored
            }
        )
        response = self._make_munki_request(
            reverse("monolith:repository_catalog", args=(self.manifest.get_catalog_munki_name(),)),
            serial_number="12345678",
            tags=[get_random_string(12) for _ in range(2)]
        )
        self.assertEqual(response.status_code, 200)
        catalog = plistlib.loads(response.content)
        self.assertEqual(len(catalog), 2)

    def test_get_catalog_two_pkgsinfo_default_shard_out_of_bounds_excluded(self):
        pkg_info1, catalog, sub_manifest = self._force_smo(name="ceci_n_est_pas_un_nom", version="1.2.3")
        pkg_info2, _, _ = self._force_smo(
            name=pkg_info1.name.name,
            version="1.2.4",
            catalog=catalog,
            sub_manifest=sub_manifest,
            zentral_monolith={
                "excluded_tags": ["EXCL1", "EXCL2"],
                "shards": {"default": -17}  # out of bounds, excluded
            }
        )
        response = self._make_munki_request(
            reverse("monolith:repository_catalog", args=(self.manifest.get_catalog_munki_name(),)),
            tags=[get_random_string(12) for _ in range(2)]
        )
        self.assertEqual(response.status_code, 200)
        catalog = plistlib.loads(response.content)
        self.assertEqual(len(catalog), 1)
        self.assertTrue(all(p.get("zentral_monolith") is None for p in catalog))
        self.assertEqual(catalog[0]["version"], "1.2.3")

    def test_get_catalog_two_pkgsinfo_tag_shard_included(self):
        pkg_info1, catalog, sub_manifest = self._force_smo(name="ceci_n_est_pas_un_nom", version="1.2.3")
        pkg_info2, _, _ = self._force_smo(
            name=pkg_info1.name.name,
            version="1.2.4",
            catalog=catalog,
            sub_manifest=sub_manifest,
            zentral_monolith={
                "excluded_tags": ["EXCL1", "EXCL2"],
                "shards": {"default": 0,  # will be ignored, because of the tag priority
                           "tags": {"INCL1": 60,  # with NAME + VERSION + SN → 59, included
                                    "INCL2": 0}}  # ignored, because the highest shard value will be used
            }
        )
        response = self._make_munki_request(
            reverse("monolith:repository_catalog", args=(self.manifest.get_catalog_munki_name(),)),
            serial_number="12345678",
            tags=["INCL1", "INCL2"]
        )
        self.assertEqual(response.status_code, 200)
        catalog = plistlib.loads(response.content)
        self.assertEqual(len(catalog), 2)

    def test_get_catalog_two_pkgsinfo_tag_shard_excluded(self):
        pkg_info1, catalog, sub_manifest = self._force_smo(name="ceci_n_est_pas_un_nom", version="1.2.3")
        pkg_info2, _, _ = self._force_smo(
            name=pkg_info1.name.name,
            version="1.2.4",
            catalog=catalog,
            sub_manifest=sub_manifest,
            zentral_monolith={
                "excluded_tags": ["EXCL1", "EXCL2"],
                "shards": {"default": 100,  # will be ignored, because of the tag priority
                           "tags": {"INCL1": 50}}  # with NAME + VERSION + SN → 59, excluded
            }
        )
        response = self._make_munki_request(
            reverse("monolith:repository_catalog", args=(self.manifest.get_catalog_munki_name(),)),
            serial_number="12345678",
            tags=["INCL1", "INCL2"]
        )
        self.assertEqual(response.status_code, 200)
        catalog = plistlib.loads(response.content)
        self.assertEqual(len(catalog), 1)
        self.assertTrue(all(p.get("zentral_monolith") is None for p in catalog))
        self.assertEqual(catalog[0]["version"], "1.2.3")

    def test_get_catalog_two_pkgsinfo_excluded_tag(self):
        pkg_info1, catalog, sub_manifest = self._force_smo(name="ceci_n_est_pas_un_nom", version="1.2.3")
        pkg_info2, _, _ = self._force_smo(
            name=pkg_info1.name.name,
            version="1.2.4",
            catalog=catalog,
            sub_manifest=sub_manifest,
            zentral_monolith={
                "excluded_tags": ["EXCL1", "EXCL2"],
                "shards": {"default": 16, "modulo": 16, "tags": {"INCL1": 16, "INCL2": 16}}  # ignored
            }
        )
        response = self._make_munki_request(
            reverse("monolith:repository_catalog", args=(self.manifest.get_catalog_munki_name(),)),
            serial_number="12345678",
            tags=["EXCL1", "INCL1", "INCL2"]
        )
        self.assertEqual(response.status_code, 200)
        catalog = plistlib.loads(response.content)
        self.assertEqual(len(catalog), 1)
        self.assertTrue(all(p.get("zentral_monolith") is None for p in catalog))
        self.assertEqual(catalog[0]["version"], "1.2.3")

    # manifest

    def test_manifest(self):
        _, catalog, sub_manifest = self._force_smo(
            name="ceci_n_est_pas_un_nom_aussi"
        )
        response = self._make_munki_request(
            reverse("monolith:repository_manifest", args=("12345678",)),
        )
        self.assertEqual(response.status_code, 200)
        serialized_manifest = plistlib.loads(response.content)
        manifest = sub_manifest.manifestsubmanifest_set.first().manifest
        self.assertEqual(
            serialized_manifest,
            {'catalogs': [f"manifest-catalog.{manifest.pk}.{manifest.name}"],
             'included_manifests': [sub_manifest.get_munki_name()],
             'managed_installs': []}
        )

    # sub manifests

    def test_sub_manifest_no_options_included(self):
        _, _, sub_manifest = self._force_smo(
            name="ceci_n_est_pas_un_nom_aussi"
        )
        response = self._make_munki_request(
            reverse("monolith:repository_manifest", args=(sub_manifest.get_munki_name(),)),
        )
        self.assertEqual(response.status_code, 200)
        sub_manifest = plistlib.loads(response.content)
        self.assertEqual(
            sub_manifest,
            {'managed_installs': ['ceci_n_est_pas_un_nom_aussi'], 'managed_uninstalls': []}
        )

    def test_sub_manifest_script_included(self):
        _, _, sub_manifest = self._force_smo(
            name="ceci_n_est_pas_un_nom_aussi",
            smo_class=SubManifestAttachment
        )
        response = self._make_munki_request(
            reverse("monolith:repository_manifest", args=(sub_manifest.get_munki_name(),)),
        )
        self.assertEqual(response.status_code, 200)
        serialized_sub_manifest = plistlib.loads(response.content)
        self.assertEqual(
            serialized_sub_manifest,
            {'managed_installs': [f'sub manifest {sub_manifest.pk} script ceci_n_est_pas_un_nom_aussi'],
             'managed_uninstalls': []}
        )

    def test_sub_manifest_no_options_default_installs_included_twice(self):
        _, _, sub_manifest = self._force_smo(
            name="ceci_n_est_pas_un_nom_aussi",
            sub_manifest_key="default_installs"
        )
        response = self._make_munki_request(
            reverse("monolith:repository_manifest", args=(sub_manifest.get_munki_name(),)),
        )
        self.assertEqual(response.status_code, 200)
        sub_manifest = plistlib.loads(response.content)
        self.assertEqual(
            sub_manifest,
            {'default_installs': ['ceci_n_est_pas_un_nom_aussi'],
             'optional_installs': ['ceci_n_est_pas_un_nom_aussi'],
             'managed_uninstalls': []}
        )

    def test_sub_manifest_script_default_installs_included_twice(self):
        _, _, sub_manifest = self._force_smo(
            name="ceci_n_est_pas_un_nom_aussi",
            sub_manifest_key="default_installs",
            smo_class=SubManifestAttachment
        )
        response = self._make_munki_request(
            reverse("monolith:repository_manifest", args=(sub_manifest.get_munki_name(),)),
        )
        self.assertEqual(response.status_code, 200)
        serialized_sub_manifest = plistlib.loads(response.content)
        self.assertEqual(
            serialized_sub_manifest,
            {'default_installs': [f'sub manifest {sub_manifest.pk} script ceci_n_est_pas_un_nom_aussi'],
             'optional_installs': [f'sub manifest {sub_manifest.pk} script ceci_n_est_pas_un_nom_aussi'],
             'managed_uninstalls': []}
        )

    def test_sub_manifest_default_shard_included(self):
        _, _, sub_manifest = self._force_smo(
            name="deuxième nom",
            smo_options={"excluded_tags": ["EXCL1", "EXCL2"],
                         "shards": {"default": 100, "tags": {"INCL1": 100, "INCL2": 100}}}
        )
        response = self._make_munki_request(
            reverse("monolith:repository_manifest", args=(sub_manifest.get_munki_name(),)),
        )
        self.assertEqual(response.status_code, 200)
        sub_manifest = plistlib.loads(response.content)
        self.assertEqual(
            sub_manifest,
            {'managed_installs': ['deuxième nom'], 'managed_uninstalls': []}
        )

    def test_sub_manifest_one_excluded_tag(self):
        _, catalog, sub_manifest = self._force_smo(name="premier nom")
        self._force_smo(
            name="deuxième nom",
            catalog=catalog,
            sub_manifest=sub_manifest,
            smo_options={"excluded_tags": ["EXCL1", "EXCL2"],
                         "shards": {"default": 100, "tags": {"INCL1": 100, "INCL2": 100}}}
        )
        response = self._make_munki_request(
            reverse("monolith:repository_manifest", args=(sub_manifest.get_munki_name(),)),
            serial_number="12345678",
            tags=["EXCL1"]
        )
        self.assertEqual(response.status_code, 200)
        sub_manifest = plistlib.loads(response.content)
        self.assertEqual(
            sub_manifest,
            {'managed_installs': ['premier nom'], 'managed_uninstalls': []}
        )

    def test_sub_manifest_one_tag_shard_excluded(self):
        _, catalog, sub_manifest = self._force_smo(name="premier nom")
        self._force_smo(
            name="deuxième nom",
            catalog=catalog,
            sub_manifest=sub_manifest,
            smo_options={"excluded_tags": ["EXCL1", "EXCL2"],
                         "shards": {"default": 0, "tags": {"INCL1": 0, "INCL2": 76}}}  # NAME + SN → 77
        )
        response = self._make_munki_request(
            reverse("monolith:repository_manifest", args=(sub_manifest.get_munki_name(),)),
            serial_number="12345678",
            tags=["INCL2"]
        )
        self.assertEqual(response.status_code, 200)
        sub_manifest = plistlib.loads(response.content)
        self.assertEqual(
            sub_manifest,
            {'managed_installs': ['premier nom'], 'managed_uninstalls': []}
        )

    def test_sub_manifest_one_tag_shard_included(self):
        _, _, sub_manifest = self._force_smo(
            name="deuxième nom",
            smo_options={"excluded_tags": ["EXCL1", "EXCL2"],
                         "shards": {"default": 0, "tags": {"INCL1": 0, "INCL2": 78}}}  # NAME + SN → 77
        )
        response = self._make_munki_request(
            reverse("monolith:repository_manifest", args=(sub_manifest.get_munki_name(),)),
            serial_number="12345678",
            tags=["INCL2"]
        )
        self.assertEqual(response.status_code, 200)
        sub_manifest = plistlib.loads(response.content)
        self.assertEqual(
            sub_manifest,
            {'managed_installs': ['deuxième nom'], 'managed_uninstalls': []}
        )

import copy
import os.path
import plistlib
from urllib.parse import urlparse
import uuid
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse, NoReverseMatch
from django.utils.crypto import get_random_string
from server.urls import build_urlpatterns_for_zentral_apps
from zentral.conf import settings
from zentral.contrib.inventory.models import EnrollmentSecret, MachineTag, MetaBusinessUnit, Tag
from zentral.contrib.monolith.models import (Enrollment,
                                             ManifestCatalog, ManifestSubManifest,
                                             PkgInfo, PkgInfoName,
                                             SubManifest, SubManifestPkgInfo)
from .utils import force_catalog, force_manifest, force_repository


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
        # repository
        cls.virtual_repository = force_repository(virtual=True)
        cls.s3_repository = force_repository(virtual=False)
        # manifest
        cls.manifest = force_manifest(mbu=cls.mbu)
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

    def _force_smpi(
        self,
        name=None,
        version=None,
        catalog=None,
        sub_manifest=None,
        sub_manifest_key=None,
        zentral_monolith=None,
        smo_options=None,
        local_pkg_content=None
    ):
        if catalog is None:
            catalog = force_catalog(repository=self.virtual_repository if local_pkg_content else self.s3_repository)
        ManifestCatalog.objects.get_or_create(manifest=self.manifest, catalog=catalog)
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
            repository=catalog.repository,
            name=pkg_info_name,
            version=version,
            data=data
        )
        pkg_info.catalogs.set([catalog])
        if local_pkg_content:
            name = get_random_string(12)
            pkg_info.file.save(name, SimpleUploadedFile(name, local_pkg_content), save=False)
            pkg_info.data["installer_item_location"] = pkg_info.file.name
            pkg_info.save()
        SubManifestPkgInfo.objects.get_or_create(
            sub_manifest=sub_manifest,
            pkg_info_name=pkg_info_name,
            defaults={"key": sub_manifest_key or "managed_installs",
                      "options": smo_options}
        )
        return pkg_info, catalog, sub_manifest

    # catalogs

    def test_get_catalog(self):
        pkg_info, catalog, _ = self._force_smpi()
        response = self._make_munki_request(
            reverse("monolith_public:repository_catalog", args=(self.manifest.get_catalog_munki_name(),))
        )
        self.assertEqual(response.status_code, 200)
        catalog = plistlib.loads(response.content)
        self.assertEqual(len(catalog), 1)
        cat_pkg_info = catalog[0]
        self.assertEqual(cat_pkg_info["name"], pkg_info.name.name)
        self.assertEqual(cat_pkg_info["version"], pkg_info.version)

    def test_get_catalog_two_pkgsinfo_no_shards(self):
        pkg_info1, catalog, sub_manifest = self._force_smpi()
        pkg_info2, _, _ = self._force_smpi(
            name=pkg_info1.name.name,
            version="1.2.4",
            catalog=catalog,
            sub_manifest=sub_manifest
        )
        response = self._make_munki_request(
            reverse("monolith_public:repository_catalog", args=(self.manifest.get_catalog_munki_name(),)),
            tags=[get_random_string(12) for _ in range(2)]
        )
        self.assertEqual(response.status_code, 200)
        catalog = plistlib.loads(response.content)
        self.assertEqual(len(catalog), 2)

    def test_get_catalog_two_pkgsinfo_default_shard_filtered_out(self):
        pkg_info1, catalog, sub_manifest = self._force_smpi(name="ceci_n_est_pas_un_nom", version="1.2.3")
        pkg_info2, _, _ = self._force_smpi(
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
            reverse("monolith_public:repository_catalog", args=(self.manifest.get_catalog_munki_name(),)),
            serial_number="12345678",
            tags=[get_random_string(12) for _ in range(2)]
        )
        self.assertEqual(response.status_code, 200)
        catalog = plistlib.loads(response.content)
        self.assertEqual(len(catalog), 1)
        self.assertTrue(all(p.get("zentral_monolith") is None for p in catalog))
        self.assertEqual(catalog[0]["version"], "1.2.3")

    def test_get_catalog_two_pkgsinfo_default_shard_included(self):
        pkg_info1, catalog, sub_manifest = self._force_smpi(name="ceci_n_est_pas_un_nom", version="1.2.3")
        pkg_info2, _, _ = self._force_smpi(
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
            reverse("monolith_public:repository_catalog", args=(self.manifest.get_catalog_munki_name(),)),
            serial_number="12345678",
            tags=[get_random_string(12) for _ in range(2)]
        )
        self.assertEqual(response.status_code, 200)
        catalog = plistlib.loads(response.content)
        self.assertEqual(len(catalog), 2)

    def test_get_catalog_two_pkgsinfo_default_shard_out_of_bounds_excluded(self):
        pkg_info1, catalog, sub_manifest = self._force_smpi(name="ceci_n_est_pas_un_nom", version="1.2.3")
        pkg_info2, _, _ = self._force_smpi(
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
            reverse("monolith_public:repository_catalog", args=(self.manifest.get_catalog_munki_name(),)),
            tags=[get_random_string(12) for _ in range(2)]
        )
        self.assertEqual(response.status_code, 200)
        catalog = plistlib.loads(response.content)
        self.assertEqual(len(catalog), 1)
        self.assertTrue(all(p.get("zentral_monolith") is None for p in catalog))
        self.assertEqual(catalog[0]["version"], "1.2.3")

    def test_get_catalog_two_pkgsinfo_tag_shard_included(self):
        pkg_info1, catalog, sub_manifest = self._force_smpi(name="ceci_n_est_pas_un_nom", version="1.2.3")
        pkg_info2, _, _ = self._force_smpi(
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
            reverse("monolith_public:repository_catalog", args=(self.manifest.get_catalog_munki_name(),)),
            serial_number="12345678",
            tags=["INCL1", "INCL2"]
        )
        self.assertEqual(response.status_code, 200)
        catalog = plistlib.loads(response.content)
        self.assertEqual(len(catalog), 2)

    def test_get_catalog_two_pkgsinfo_tag_shard_excluded(self):
        pkg_info1, catalog, sub_manifest = self._force_smpi(name="ceci_n_est_pas_un_nom", version="1.2.3")
        pkg_info2, _, _ = self._force_smpi(
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
            reverse("monolith_public:repository_catalog", args=(self.manifest.get_catalog_munki_name(),)),
            serial_number="12345678",
            tags=["INCL1", "INCL2"]
        )
        self.assertEqual(response.status_code, 200)
        catalog = plistlib.loads(response.content)
        self.assertEqual(len(catalog), 1)
        self.assertTrue(all(p.get("zentral_monolith") is None for p in catalog))
        self.assertEqual(catalog[0]["version"], "1.2.3")

    def test_get_catalog_two_pkgsinfo_excluded_tag(self):
        pkg_info1, catalog, sub_manifest = self._force_smpi(name="ceci_n_est_pas_un_nom", version="1.2.3")
        pkg_info2, _, _ = self._force_smpi(
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
            reverse("monolith_public:repository_catalog", args=(self.manifest.get_catalog_munki_name(),)),
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
        _, catalog, sub_manifest = self._force_smpi(
            name="ceci_n_est_pas_un_nom_aussi"
        )
        response = self._make_munki_request(
            reverse("monolith_public:repository_manifest", args=("12345678",)),
        )
        self.assertEqual(response.status_code, 200)
        serialized_manifest = plistlib.loads(response.content)
        manifest = sub_manifest.manifestsubmanifest_set.first().manifest
        self.assertEqual(
            serialized_manifest,
            {'catalogs': [f"manifest-catalog.{manifest.pk}.{manifest.name}"],
             'included_manifests': [sub_manifest.get_munki_name()]}
        )

    # sub manifests

    def test_sub_manifest_no_options_included(self):
        _, _, sub_manifest = self._force_smpi(
            name="ceci_n_est_pas_un_nom_aussi"
        )
        response = self._make_munki_request(
            reverse("monolith_public:repository_manifest", args=(sub_manifest.get_munki_name(),)),
        )
        self.assertEqual(response.status_code, 200)
        sub_manifest = plistlib.loads(response.content)
        self.assertEqual(
            sub_manifest,
            {'managed_installs': ['ceci_n_est_pas_un_nom_aussi']}
        )

    def test_sub_manifest_no_options_default_installs_included_twice(self):
        _, _, sub_manifest = self._force_smpi(
            name="ceci_n_est_pas_un_nom_aussi",
            sub_manifest_key="default_installs"
        )
        response = self._make_munki_request(
            reverse("monolith_public:repository_manifest", args=(sub_manifest.get_munki_name(),)),
        )
        self.assertEqual(response.status_code, 200)
        sub_manifest = plistlib.loads(response.content)
        self.assertEqual(
            sub_manifest,
            {'default_installs': ['ceci_n_est_pas_un_nom_aussi'],
             'optional_installs': ['ceci_n_est_pas_un_nom_aussi']}
        )

    def test_sub_manifest_default_shard_included(self):
        _, _, sub_manifest = self._force_smpi(
            name="deuxième nom",
            smo_options={"excluded_tags": ["EXCL1", "EXCL2"],
                         "shards": {"default": 100, "tags": {"INCL1": 100, "INCL2": 100}}}
        )
        response = self._make_munki_request(
            reverse("monolith_public:repository_manifest", args=(sub_manifest.get_munki_name(),)),
        )
        self.assertEqual(response.status_code, 200)
        sub_manifest = plistlib.loads(response.content)
        self.assertEqual(
            sub_manifest,
            {'managed_installs': ['deuxième nom']}
        )

    def test_sub_manifest_one_excluded_tag(self):
        _, catalog, sub_manifest = self._force_smpi(name="premier nom")
        self._force_smpi(
            name="deuxième nom",
            catalog=catalog,
            sub_manifest=sub_manifest,
            smo_options={"excluded_tags": ["EXCL1", "EXCL2"],
                         "shards": {"default": 100, "tags": {"INCL1": 100, "INCL2": 100}}}
        )
        response = self._make_munki_request(
            reverse("monolith_public:repository_manifest", args=(sub_manifest.get_munki_name(),)),
            serial_number="12345678",
            tags=["EXCL1"]
        )
        self.assertEqual(response.status_code, 200)
        sub_manifest = plistlib.loads(response.content)
        self.assertEqual(
            sub_manifest,
            {'managed_installs': ['premier nom']}
        )

    def test_sub_manifest_one_tag_shard_excluded(self):
        _, catalog, sub_manifest = self._force_smpi(name="premier nom")
        self._force_smpi(
            name="deuxième nom",
            catalog=catalog,
            sub_manifest=sub_manifest,
            smo_options={"excluded_tags": ["EXCL1", "EXCL2"],
                         "shards": {"default": 0, "tags": {"INCL1": 0, "INCL2": 76}}}  # NAME + SN → 77
        )
        response = self._make_munki_request(
            reverse("monolith_public:repository_manifest", args=(sub_manifest.get_munki_name(),)),
            serial_number="12345678",
            tags=["INCL2"]
        )
        self.assertEqual(response.status_code, 200)
        sub_manifest = plistlib.loads(response.content)
        self.assertEqual(
            sub_manifest,
            {'managed_installs': ['premier nom']}
        )

    def test_sub_manifest_one_tag_shard_included(self):
        _, _, sub_manifest = self._force_smpi(
            name="deuxième nom",
            smo_options={"excluded_tags": ["EXCL1", "EXCL2"],
                         "shards": {"default": 0, "tags": {"INCL1": 0, "INCL2": 78}}}  # NAME + SN → 77
        )
        response = self._make_munki_request(
            reverse("monolith_public:repository_manifest", args=(sub_manifest.get_munki_name(),)),
            serial_number="12345678",
            tags=["INCL2"]
        )
        self.assertEqual(response.status_code, 200)
        sub_manifest = plistlib.loads(response.content)
        self.assertEqual(
            sub_manifest,
            {'managed_installs': ['deuxième nom']}
        )

    # repository package

    def test_repository_package(self):
        pkg_info, _, _ = self._force_smpi()
        api_path = pkg_info.get_pkg_info()["installer_item_location"]
        response = self._make_munki_request(reverse("monolith_public:repository_package", args=(api_path,)))
        self.assertEqual(response.status_code, 302)
        p = urlparse(response.url)
        self.assertEqual(p.scheme, "https")
        self.assertEqual(p.netloc, "s3.us-east1.amazonaws.com")
        s3_repo_kwargs = self.s3_repository.get_backend_kwargs()
        self.assertEqual(
            p.path,
            os.path.join(
                "/",
                s3_repo_kwargs["bucket"],
                s3_repo_kwargs["prefix"],
                "pkgs",
                pkg_info.data["installer_item_location"]
            )
        )

    def test_unknown_repository_package(self):
        pkg_info, _, _ = self._force_smpi()
        api_path = pkg_info.get_pkg_info()["installer_item_location"]
        api_path = api_path.replace("." + str(pkg_info.pk) + ".", ".0.")  # no pkg info with pk == 0
        response = self._make_munki_request(reverse("monolith_public:repository_package", args=(api_path,)))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content, b"Not found!")

    def test_local_repository_package_not_found(self):
        pkg_info, _, _ = self._force_smpi(local_pkg_content=b"fomo")
        api_path = pkg_info.get_pkg_info()["installer_item_location"]
        pkg_info.file.delete()
        response = self._make_munki_request(reverse("monolith_public:repository_package", args=(api_path,)))
        self.assertEqual(response.status_code, 404)

    def test_local_repository_package(self):
        pkg_info, _, _ = self._force_smpi(local_pkg_content=b"fomo")
        api_path = pkg_info.get_pkg_info()["installer_item_location"]
        response = self._make_munki_request(reverse("monolith_public:repository_package", args=(api_path,)))
        self.assertEqual(b"".join(response.streaming_content), b"fomo")
        pkg_info.file.delete(save=False)

    # icon hashes

    def test_icon_hashes(self):
        repository1 = force_repository()
        repository1.icon_hashes = {"un": 64 * "a"}
        repository1.save()
        force_catalog(repository=repository1, manifest=self.manifest)
        repository2 = force_repository()
        repository2.icon_hashes = {"deux": 64 * "b"}
        repository2.save()
        force_catalog(repository=repository2, manifest=self.manifest)
        response = self._make_munki_request(reverse("monolith_public:repository_icon_hashes"))
        self.assertEqual(
            plistlib.loads(response.content),
            {"un": 64 * "a", "deux": 64 * "b"}
        )

    # client resources

    def test_client_resource_redirect(self):
        repository = force_repository()
        repository.client_resources = ["yolo.zip"]
        repository.save()
        force_catalog(repository=repository, manifest=self.manifest)
        response = self._make_munki_request(reverse("monolith_public:repository_client_resource",
                                                    args=("yolo.zip",)))
        self.assertEqual(response.status_code, 302)
        p = urlparse(response.url)
        self.assertEqual(p.scheme, "https")
        self.assertEqual(p.netloc, "s3.us-east1.amazonaws.com")
        s3_repo_kwargs = repository.get_backend_kwargs()
        self.assertEqual(
            p.path,
            os.path.join(
                "/",
                s3_repo_kwargs["bucket"],
                s3_repo_kwargs.get("prefix", ""),
                "client_resources",
                "yolo.zip"
            )
        )

    def test_client_resource_not_found(self):
        repository = force_repository()
        repository.client_resources = ["yolo.zip"]
        repository.save()
        force_catalog(repository=repository, manifest=self.manifest)
        response = self._make_munki_request(reverse("monolith_public:repository_client_resource",
                                                    args=("fomo.zip",)))
        self.assertEqual(response.status_code, 404)

    # legacy URLs

    def test_legacy_public_urls_are_disabled_on_tests(self):
        routes = [
            'repository_catalog',
            'repository_manifest',
            'repository_package',
            'repository_icon',
            'repository_client_resource',
        ]
        for route in routes:
            with self.assertRaises(NoReverseMatch):
                reverse(f"monolith_public_legacy:{route}", args=("path",),)
            self.assertIsNotNone(reverse(f"monolith_public:{route}", args=("path",),))

    def test_mount_legacy_public_endpoints_flag_is_working(self):
        url_prefix = "/public"
        routes = [
            'repository_catalog',
            'repository_manifest',
            'repository_package',
            'repository_icon',
            'repository_client_resource',
        ]
        munki_conf = settings._collection["apps"]._collection["zentral.contrib.monolith"]
        munki_conf._collection["mount_legacy_public_endpoints"] = True
        urlpatterns_w_legacy = tuple(build_urlpatterns_for_zentral_apps())
        munki_conf._collection["mount_legacy_public_endpoints"] = False
        urlpatterns_wo_legacy = tuple(build_urlpatterns_for_zentral_apps())
        for route in routes:
            self.assertEqual(
                reverse(f"monolith_public:{route}", args=("path",), urlconf=urlpatterns_w_legacy),
                url_prefix + reverse(f"monolith_public_legacy:{route}", args=("path",), urlconf=urlpatterns_w_legacy)
            )
            with self.assertRaises(NoReverseMatch):
                reverse(f"monolith_public_legacy:{route}", args=("path",), urlconf=urlpatterns_wo_legacy)

from datetime import datetime
import random
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit, Tag
from zentral.contrib.monolith.conf import monolith_conf
from zentral.contrib.monolith.models import (Catalog, Manifest, ManifestCatalog, ManifestEnrollmentPackage,
                                             ManifestSubManifest, PkgInfo, PkgInfoName, SubManifest)
from zentral.contrib.munki.models import ManagedInstall


def sorted_objects(object_list):
    return sorted(object_list, key=lambda o: o.pk)


class MonolithModelsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.meta_business_unit = MetaBusinessUnit.objects.create(name=get_random_string(13))
        cls.manifest = Manifest.objects.create(meta_business_unit=cls.meta_business_unit, name=get_random_string(13))
        cls.catalog_1 = Catalog.objects.create(name=get_random_string(13), priority=10)
        cls.catalog_2 = Catalog.objects.create(name=get_random_string(13), priority=20)
        cls.sub_manifest_1 = SubManifest.objects.create(
            meta_business_unit=cls.meta_business_unit, name=get_random_string(13))
        cls.sub_manifest_2 = SubManifest.objects.create(
            meta_business_unit=cls.meta_business_unit, name=get_random_string(13))
        cls.tag_1 = Tag.objects.create(name=get_random_string(13))
        cls.tag_2 = Tag.objects.create(name=get_random_string(13))
        cls.tag_3 = Tag.objects.create(name=get_random_string(13))
        ManifestCatalog.objects.create(manifest=cls.manifest, catalog=cls.catalog_1)
        mc = ManifestCatalog.objects.create(manifest=cls.manifest, catalog=cls.catalog_2)
        mc.tags.set([cls.tag_1, cls.tag_2])
        ManifestSubManifest.objects.create(manifest=cls.manifest, sub_manifest=cls.sub_manifest_1)
        msm = ManifestSubManifest.objects.create(manifest=cls.manifest, sub_manifest=cls.sub_manifest_2)
        msm.tags.set([cls.tag_1, cls.tag_2])
        cls.builder = random.choice(list(monolith_conf.enrollment_package_builders.keys()))
        cls.mep_1 = ManifestEnrollmentPackage.objects.create(manifest=cls.manifest, builder=cls.builder)
        cls.mep_2 = ManifestEnrollmentPackage.objects.create(manifest=cls.manifest, builder=cls.builder)
        cls.mep_2.tags.set([cls.tag_1, cls.tag_2])
        cls.pkginfo_name_1 = PkgInfoName.objects.create(name="aaaa first name")
        cls.pkginfo_1_1 = PkgInfo.objects.create(name=cls.pkginfo_name_1, version="1.0",
                                                 data={"name": cls.pkginfo_name_1.name,
                                                       "version": "1.0",
                                                       "zentral_monolith": {
                                                           "shards": {"modulo": 17}
                                                        }})
        cls.pkginfo_1_1.catalogs.set([cls.catalog_1, cls.catalog_2])
        cls.pkginfo_1_2 = PkgInfo.objects.create(name=cls.pkginfo_name_1, version="2.0",
                                                 data={"name": cls.pkginfo_name_1.name,
                                                       "version": "2.0",
                                                       "zentral_monolith": {
                                                           "excluded_tags": [cls.tag_1.name],
                                                           "shards": {
                                                               "default": 0,
                                                               "modulo": 16,
                                                               "tags": {cls.tag_2.name: 12}
                                                            }
                                                        }})
        cls.pkginfo_1_2.catalogs.set([cls.catalog_2])
        cls.pkginfo_name_2 = PkgInfoName.objects.create(name="bbbb second name")
        cls.pkginfo_2_1 = PkgInfo.objects.create(name=cls.pkginfo_name_2, version="1.0",
                                                 data={"name": cls.pkginfo_name_2.name,
                                                       "version": "1.0"})
        cls.pkginfo_2_1.catalogs.set([cls.catalog_1, cls.catalog_2])
        # simulate 1 install of 1v1 and 3 installs of 1v2, 1 install of 2v1
        ManagedInstall.objects.create(
            machine_serial_number=get_random_string(12),
            name=cls.pkginfo_name_1.name,
            installed_version=cls.pkginfo_1_1.version,
            installed_at=datetime.utcnow()
        )
        for i in range(3):
            ManagedInstall.objects.create(
                machine_serial_number=get_random_string(12),
                name=cls.pkginfo_name_1.name,
                installed_version=cls.pkginfo_1_2.version,
                installed_at=datetime.utcnow()
            )
        ManagedInstall.objects.create(
            machine_serial_number=get_random_string(12),
            name=cls.pkginfo_name_2.name,
            installed_version=cls.pkginfo_2_1.version,
            installed_at=datetime.utcnow()
        )

    def test_manifest_sub_manifest(self):
        self.assertEqual(self.manifest.sub_manifest(self.sub_manifest_1.pk),
                         self.sub_manifest_1)
        self.assertEqual(self.manifest.sub_manifest(self.sub_manifest_1.pk, [self.tag_1, self.tag_3]),
                         self.sub_manifest_1)
        self.assertEqual(self.manifest.sub_manifest(self.sub_manifest_2.pk),
                         None)
        self.assertEqual(self.manifest.sub_manifest(self.sub_manifest_2.pk, [self.tag_3]),
                         None)
        self.assertEqual(self.manifest.sub_manifest(self.sub_manifest_2.pk, [self.tag_1]),
                         self.sub_manifest_2)
        self.assertEqual(self.manifest.sub_manifest(self.sub_manifest_2.pk, [self.tag_2]),
                         self.sub_manifest_2)
        self.assertEqual(self.manifest.sub_manifest(self.sub_manifest_2.pk, [self.tag_2, self.tag_3]),
                         self.sub_manifest_2)
        self.assertEqual(self.manifest.sub_manifest(self.sub_manifest_2.pk, [self.tag_1, self.tag_2]),
                         self.sub_manifest_2)

    def test_manifest_sub_manifests(self):
        self.assertEqual(self.manifest.sub_manifests(),
                         [self.sub_manifest_1])
        self.assertEqual(self.manifest.sub_manifests([self.tag_3]),
                         [self.sub_manifest_1])
        self.assertEqual(sorted_objects(self.manifest.sub_manifests([self.tag_1, self.tag_3])),
                         sorted_objects([self.sub_manifest_1, self.sub_manifest_2]))
        self.assertEqual(sorted_objects(self.manifest.sub_manifests([self.tag_2])),
                         sorted_objects([self.sub_manifest_1, self.sub_manifest_2]))
        self.assertEqual(sorted_objects(self.manifest.sub_manifests([self.tag_2, self.tag_1])),
                         sorted_objects([self.sub_manifest_1, self.sub_manifest_2]))

    def test_manifest_catalogs(self):
        self.assertEqual(self.manifest.catalogs(),
                         [self.catalog_1])
        self.assertEqual(self.manifest.catalogs([self.tag_3]),
                         [self.catalog_1])
        self.assertEqual(sorted_objects(self.manifest.catalogs([self.tag_1, self.tag_3])),
                         sorted_objects([self.catalog_1, self.catalog_2]))
        self.assertEqual(sorted_objects(self.manifest.catalogs([self.tag_2])),
                         sorted_objects([self.catalog_1, self.catalog_2]))
        self.assertEqual(sorted_objects(self.manifest.catalogs([self.tag_2, self.tag_1])),
                         sorted_objects([self.catalog_1, self.catalog_2]))

    def test_manifest_enrollment_package(self):
        self.assertEqual(self.manifest.enrollment_packages(),
                         {self.builder: self.mep_1})
        self.assertEqual(self.manifest.enrollment_packages([self.tag_3]),
                         {self.builder: self.mep_1})
        self.assertEqual(self.manifest.enrollment_packages([self.tag_1, self.tag_3]),
                         {self.builder: self.mep_1})
        self.assertEqual(self.manifest.enrollment_packages([self.tag_2]),
                         {self.builder: self.mep_1})
        # Only with fully matching tags do we get the second manifest enrollment package
        self.assertEqual(self.manifest.enrollment_packages([self.tag_2, self.tag_1]),
                         {self.builder: self.mep_2})

    # PkgInfo.objects.alles

    def test_alles_all(self):
        name_c, info_c, pkg_name_list = PkgInfo.objects.alles()
        self.assertEqual(name_c, 2)
        self.assertEqual(info_c, 3)
        self.assertEqual(len(pkg_name_list), 2)

        pkg_name_r_1 = pkg_name_list[0]
        self.assertEqual(len(pkg_name_r_1["pkg_infos"]), 2)
        self.assertEqual(pkg_name_r_1["name"], "aaaa first name")
        for pkg_info_r in pkg_name_r_1["pkg_infos"]:
            options = pkg_info_r["options"]
            if pkg_info_r["version"] == "1.0":
                self.assertNotIn("excluded_tags", options)
                shards = options["shards"]
                self.assertEqual(shards["default"], 17)
                self.assertEqual(shards["modulo"], 17)
                self.assertNotIn("tags", shards)
                self.assertEqual(len(pkg_info_r["catalogs"]), 2)
                self.assertEqual(pkg_info_r["count"], 1)
                self.assertEqual(pkg_info_r["percent"], 25)
            else:
                self.assertEqual(options["excluded_tags"], [self.tag_1])
                shards = options["shards"]
                self.assertEqual(shards["default"], 0)
                self.assertEqual(shards["modulo"], 16)
                self.assertEqual(shards["tags"], [(self.tag_2, 12)])
                self.assertEqual(len(pkg_info_r["catalogs"]), 1)
                self.assertEqual(pkg_info_r["count"], 3)
                self.assertEqual(pkg_info_r["percent"], 75)
        self.assertEqual(pkg_name_r_1["count"], 4)

        pkg_name_r_2 = pkg_name_list[1]
        self.assertEqual(pkg_name_r_2["name"], "bbbb second name")
        self.assertEqual(len(pkg_name_r_2["pkg_infos"]), 1)
        for pkg_info_r in pkg_name_r_2["pkg_infos"]:
            self.assertNotIn("options", pkg_info_r)
            self.assertEqual(len(pkg_info_r["catalogs"]), 2)
            self.assertEqual(pkg_info_r["count"], 1)
            self.assertEqual(pkg_info_r["percent"], 100)
        self.assertEqual(pkg_name_r_2["count"], 1)

    def test_alles_name(self):
        name_c, info_c, pkg_name_list = PkgInfo.objects.alles(name="first")
        self.assertEqual(name_c, 1)
        self.assertEqual(info_c, 2)
        self.assertEqual(len(pkg_name_list), 1)

        pkg_name_r_1 = pkg_name_list[0]
        self.assertEqual(len(pkg_name_r_1["pkg_infos"]), 2)
        for pkg_info_r in pkg_name_r_1["pkg_infos"]:
            if pkg_info_r["version"] == "1.0":
                self.assertEqual(len(pkg_info_r["catalogs"]), 2)
                self.assertEqual(pkg_info_r["count"], 1)
                self.assertEqual(pkg_info_r["percent"], 25)
            else:
                self.assertEqual(len(pkg_info_r["catalogs"]), 1)
                self.assertEqual(pkg_info_r["count"], 3)
                self.assertEqual(pkg_info_r["percent"], 75)
        self.assertEqual(pkg_name_r_1["count"], 4)

    def test_alles_name_id(self):
        name_c, info_c, pkg_name_list = PkgInfo.objects.alles(name_id=self.pkginfo_name_2.pk)
        self.assertEqual(name_c, 1)
        self.assertEqual(info_c, 1)
        self.assertEqual(len(pkg_name_list), 1)

        pkg_name_r_2 = pkg_name_list[0]
        self.assertEqual(len(pkg_name_r_2["pkg_infos"]), 1)
        for pkg_info_r in pkg_name_r_2["pkg_infos"]:
            self.assertEqual(len(pkg_info_r["catalogs"]), 2)
            self.assertEqual(pkg_info_r["count"], 1)
            self.assertEqual(pkg_info_r["percent"], 100)
        self.assertEqual(pkg_name_r_2["count"], 1)

    def test_alles_catalog(self):
        name_c, info_c, pkg_name_list = PkgInfo.objects.alles(catalog=self.catalog_1)
        self.assertEqual(name_c, 2)
        self.assertEqual(info_c, 2)
        self.assertEqual(len(pkg_name_list), 2)

        pkg_name_r_1 = pkg_name_list[0]
        self.assertEqual(len(pkg_name_r_1["pkg_infos"]), 1)
        for pkg_info_r in pkg_name_r_1["pkg_infos"]:
            self.assertEqual(pkg_info_r["version"], self.pkginfo_1_1.version)
            self.assertEqual(len(pkg_info_r["catalogs"]), 1)
            self.assertEqual(pkg_info_r["count"], 1)  # count do not change with a catalog filter
            self.assertEqual(pkg_info_r["percent"], 25)  # idem
        self.assertEqual(pkg_name_r_1["count"], 4)  # idem

        pkg_name_r_2 = pkg_name_list[1]
        self.assertEqual(len(pkg_name_r_2["pkg_infos"]), 1)
        for pkg_info_r in pkg_name_r_2["pkg_infos"]:
            self.assertEqual(len(pkg_info_r["catalogs"]), 1)  # this changes
            self.assertEqual(pkg_info_r["count"], 1)
            self.assertEqual(pkg_info_r["percent"], 100)
        self.assertEqual(pkg_name_r_2["count"], 1)

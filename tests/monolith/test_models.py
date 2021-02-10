import random
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit, Tag
from zentral.contrib.monolith.conf import monolith_conf
from zentral.contrib.monolith.models import (Catalog, Manifest, ManifestCatalog, ManifestEnrollmentPackage,
                                             ManifestSubManifest, SubManifest)


def sorted_objects(object_list):
    return sorted(object_list, key=lambda o: o.pk)


class MonolithSetupViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.meta_business_unit = MetaBusinessUnit.objects.create(name=get_random_string(13))
        cls.manifest = Manifest.objects.create(meta_business_unit=cls.meta_business_unit, name=get_random_string(13))
        cls.catalog_1 = Catalog.objects.create(name=get_random_string(13))
        cls.catalog_2 = Catalog.objects.create(name=get_random_string(13))
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

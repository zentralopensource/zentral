from datetime import datetime
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import EnrollmentSecret, Tag
from zentral.contrib.inventory.terraform import TagResource
from zentral.contrib.monolith.models import (Catalog, Condition, Enrollment,
                                             Manifest, ManifestCatalog, ManifestSubManifest,
                                             PkgInfoName,
                                             SubManifest, SubManifestPkgInfo)
from zentral.contrib.monolith.terraform import SubManifestPkgInfoResource, SubManifestResource


class MonolithTerraformTestCase(TestCase):
    maxDiff = None

    # utility methods

    def force_catalog(self, name=None, archived=False):
        if name is None:
            name = get_random_string(12)
        archived_at = None
        if archived:
            archived_at = datetime.utcnow()
        return Catalog.objects.create(name=name, priority=1, archived_at=archived_at)

    def force_condition(self):
        return Condition.objects.create(
            name=get_random_string(),
            predicate=get_random_string()
        )

    def force_enrollment(self, tag_count=0):
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=self.mbu)
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(tag_count)]
        if tags:
            enrollment_secret.tags.set(tags)
        return (
            Enrollment.objects.create(manifest=self.force_manifest(), secret=enrollment_secret),
            tags
        )

    def force_manifest(self, mbu=None, name=None):
        if mbu is None:
            mbu = self.mbu
        if name is None:
            name = get_random_string(12)
        return Manifest.objects.create(meta_business_unit=mbu, name=name)

    def force_manifest_catalog(self, tag=None):
        manifest = self.force_manifest()
        catalog = self.force_catalog()
        mc = ManifestCatalog.objects.create(manifest=manifest, catalog=catalog)
        if tag:
            mc.tags.add(tag)
        return mc

    def force_manifest_sub_manifest(self, tag=None):
        manifest = self.force_manifest()
        sub_manifest = self.force_sub_manifest()
        msm = ManifestSubManifest.objects.create(manifest=manifest, sub_manifest=sub_manifest)
        if tag:
            msm.tags.add(tag)
        return msm

    def force_pkg_info_name(self):
        return PkgInfoName.objects.create(name=get_random_string(12))

    def force_sub_manifest(self, meta_business_unit=None):
        return SubManifest.objects.create(
            name=get_random_string(12),
            description=get_random_string(12),
            meta_business_unit=meta_business_unit
        )

    def force_sub_manifest_pkg_info(self, sub_manifest=None, options=None):
        if sub_manifest is None:
            sub_manifest = self.force_sub_manifest()
        if options is None:
            options = {}
        return SubManifestPkgInfo.objects.create(
            sub_manifest=sub_manifest,
            key="managed_installs",
            pkg_info_name=self.force_pkg_info_name(),
            options=options
        )

    # sub manifest pkg info

    def test_sub_manifest_pkg_info_no_options_representation(self):
        smpi = self.force_sub_manifest_pkg_info()
        resource = SubManifestPkgInfoResource(smpi)
        self.assertEqual(
            resource.to_representation(),
            (f'resource "zentral_monolith_sub_manifest_pkg_info" "submanifestpkginfo{smpi.pk}" {{\n'
             f'  sub_manifest_id = zentral_monolith_sub_manifest.submanifest{smpi.sub_manifest.pk}.id\n'
             '  key             = "managed_installs"\n'
             f'  pkg_info_name   = "{smpi.pkg_info_name.name}"\n'
             '}')
        )

    def test_sub_manifest_pkg_info_all_options_representation(self):
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        sharded_tag = Tag.objects.create(name=get_random_string(12))
        smpi = self.force_sub_manifest_pkg_info(options={
            "excluded_tags": [excluded_tag.name],
            "shards": {
                "default": 1,
                "modulo": 5,
                "tags": {
                    sharded_tag.name: 3,
                }
            }
        })
        resource = SubManifestPkgInfoResource(smpi)
        self.assertEqual(
            resource.to_representation(),
            (f'resource "zentral_monolith_sub_manifest_pkg_info" "submanifestpkginfo{smpi.pk}" {{\n'
             f'  sub_manifest_id  = zentral_monolith_sub_manifest.submanifest{smpi.sub_manifest.pk}.id\n'
             '  key              = "managed_installs"\n'
             f'  pkg_info_name    = "{smpi.pkg_info_name.name}"\n'
             '  shard_modulo     = 5\n'
             '  default_shard    = 1\n'
             f'  excluded_tag_ids = [zentral_tag.tag{excluded_tag.pk}.id]\n'
             f'  tag_shards       = [{{ tag_id = zentral_tag.tag{sharded_tag.pk}.id, shard = 3 }}]\n'
             '}')
        )

    def test_sub_manifest_pkg_info_no_options_dependencies(self):
        smpi = self.force_sub_manifest_pkg_info()
        resource = SubManifestPkgInfoResource(smpi)
        dependencies = list(resource.iter_dependencies())
        self.assertEqual(len(dependencies), 1)
        self.assertIn(SubManifestResource(smpi.sub_manifest), dependencies)

    def test_sub_manifest_pkg_info_all_options_dependencies(self):
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        sharded_tag = Tag.objects.create(name=get_random_string(12))
        smpi = self.force_sub_manifest_pkg_info(options={
            "excluded_tags": [excluded_tag.name],
            "shards": {
                "default": 1,
                "modulo": 5,
                "tags": {
                    sharded_tag.name: 3,
                }
            }
        })
        resource = SubManifestPkgInfoResource(smpi)
        dependencies = list(resource.iter_dependencies())
        self.assertEqual(len(dependencies), 3)
        self.assertIn(TagResource(excluded_tag), dependencies)
        self.assertIn(TagResource(sharded_tag), dependencies)
        self.assertIn(SubManifestResource(smpi.sub_manifest), dependencies)

from io import StringIO
from unittest.mock import PropertyMock, patch
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from zentral.contrib.monolith.models import ManifestEnrollmentPackage
from .utils import force_manifest, force_manifest_enrollment_package


class RebuildManifestEnrollmentPackagesTestCase(TestCase):
    def call_command(self, *args, **kwargs):
        stdout = StringIO()
        stderr = StringIO()
        call_command("rebuild_manifest_enrollment_packages", *args, stdout=stdout, stderr=stderr, **kwargs)
        return stdout.getvalue(), stderr.getvalue()

    @staticmethod
    def force_mep(manifest=None, module="osquery"):
        mep = force_manifest_enrollment_package(manifest=manifest, module=module)
        mep.refresh_from_db()
        return mep

    def test_rebuild_all(self):
        mep = self.force_mep()
        manifest = mep.manifest
        manifest_version = manifest.version
        stdout, stderr = self.call_command()
        mep.refresh_from_db()
        manifest.refresh_from_db()
        self.assertEqual(stderr, "")
        self.assertIn(f"{mep.file.name} rebuilt", stdout)
        self.assertIn(f"Bump manifest {manifest.name} version {manifest_version} → {manifest_version + 1}", stdout)
        self.assertEqual(manifest.version, manifest_version + 1)

    def test_rebuild_with_a_storage_without_a_local_path(self):
        mep = self.force_mep()
        with patch("django.db.models.fields.files.FieldFile.path",
                   new_callable=PropertyMock, side_effect=NotImplementedError):
            stdout, stderr = self.call_command()
        self.assertEqual(stderr, "")
        self.assertTrue(stdout.startswith(f"{mep.file.name} rebuilt\n"))

    def test_rebuild_with_an_orphan_file_at_the_target_name(self):
        mep = self.force_mep()
        filename = mep.file.name
        # leave the file behind as an orphan occupying the target name,
        # like a rolled back transaction or a previous test run would
        ManifestEnrollmentPackage.objects.filter(pk=mep.pk).update(file="")
        mep.refresh_from_db()
        stdout, stderr = self.call_command()
        mep.refresh_from_db()
        self.assertEqual(stderr, "")
        self.assertEqual(mep.file.name, filename)
        self.assertIn(f"{filename} rebuilt", stdout)

    def test_rebuild_all_quiet(self):
        self.force_mep()
        stdout, stderr = self.call_command(verbosity=0)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")

    def test_rebuild_keeps_the_versions(self):
        mep = self.force_mep()
        enrollment = mep.get_enrollment()
        filename = mep.get_installer_item_filename()
        self.call_command()
        mep.refresh_from_db()
        enrollment.refresh_from_db()
        # a rebuild changes no version, so the machines that are up to date do not install the package again
        self.assertEqual(mep.version, 1)
        self.assertEqual(mep.pkg_info["version"], "1.0")
        self.assertEqual(mep.get_installer_item_filename(), filename)
        self.assertIn(f'[[ "$ENROLLMENT_VERSION" != "{enrollment.version}" ]]',
                      mep.pkg_info["installcheck_script"])

    def test_rebuild_new_version(self):
        mep = self.force_mep()
        enrollment = mep.get_enrollment()
        enrollment_version = enrollment.version
        filename = mep.get_installer_item_filename()
        self.call_command("--new-version")
        mep.refresh_from_db()
        enrollment.refresh_from_db()
        self.assertEqual(mep.version, 2)
        self.assertEqual(mep.pkg_info["version"], "2.0")
        self.assertNotEqual(mep.get_installer_item_filename(), filename)
        # the enrollment version does not change, so the installcheck script keeps the same test
        self.assertEqual(enrollment.version, enrollment_version)
        self.assertIn(f'[[ "$ENROLLMENT_VERSION" != "{enrollment_version}" ]]',
                      mep.pkg_info["installcheck_script"])

    def test_rebuild_one_manifest(self):
        mep = self.force_mep()
        other_mep = self.force_mep()
        other_manifest_version = other_mep.manifest.version
        stdout, stderr = self.call_command("--manifest", str(mep.manifest.pk))
        mep.manifest.refresh_from_db()
        other_mep.manifest.refresh_from_db()
        self.assertEqual(stderr, "")
        self.assertIn(f"Bump manifest {mep.manifest.name}", stdout)
        self.assertNotIn(f"Bump manifest {other_mep.manifest.name}", stdout)
        self.assertEqual(other_mep.manifest.version, other_manifest_version)

    def test_rebuild_two_manifests(self):
        mep = self.force_mep()
        other_mep = self.force_mep()
        stdout, _ = self.call_command("--manifest", str(mep.manifest.pk), str(other_mep.manifest.pk))
        self.assertIn(f"Bump manifest {mep.manifest.name}", stdout)
        self.assertIn(f"Bump manifest {other_mep.manifest.name}", stdout)

    def test_rebuild_one_manifest_with_a_new_version(self):
        mep = self.force_mep()
        other_mep = self.force_mep()
        enrollment = mep.get_enrollment()
        enrollment_version = enrollment.version
        self.call_command("--manifest", str(mep.manifest.pk), "--new-version")
        mep.refresh_from_db()
        other_mep.refresh_from_db()
        enrollment.refresh_from_db()
        self.assertEqual(mep.version, 2)
        # the other manifest keeps its enrollment package, and the enrollment keeps its version
        self.assertEqual(other_mep.version, 1)
        self.assertEqual(enrollment.version, enrollment_version)

    def test_rebuild_unknown_manifest(self):
        with self.assertRaises(CommandError) as cm:
            self.call_command("--manifest", "9999999", "9999998")
        self.assertEqual(cm.exception.args[0], "Unknown manifest: 9999998, 9999999")

    def test_rebuild_manifest_without_enrollment_package(self):
        manifest = force_manifest()
        stdout, stderr = self.call_command("--manifest", str(manifest.pk))
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, f"Manifest {manifest.pk} has no enrollment package\n")

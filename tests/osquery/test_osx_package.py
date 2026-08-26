import gzip
import io
import os
import plistlib
import subprocess
import tempfile
from unittest.mock import patch
from django.test import TestCase
from zentral.contrib.monolith.utils import make_package_info
from zentral.contrib.osquery.osx_package.builder import (LAUNCH_DAEMON_LABEL, LAUNCH_DAEMON_PLIST,
                                                        OSQUERYD_PATHS, OsqueryZentralEnrollPkgBuilder)
from .utils import force_enrollment


ORBIT_PATH = "/opt/orbit/bin/osqueryd/macos-app/stable/osquery.app/Contents/MacOS/osqueryd"
STANDARD_PATH = "/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd"


class OsqueryOSXPackageTestCase(TestCase):
    @staticmethod
    def _extract_scripts(package_content):
        with tempfile.TemporaryDirectory() as tmpdir:
            package_path = os.path.join(tmpdir, "test.pkg")
            with open(package_path, "wb") as f:
                f.write(package_content)
            scripts_arch = subprocess.run(["xar", "-f", package_path, "-x", "--to-stdout", "Scripts"],
                                          capture_output=True, check=True).stdout
            scripts_dir = os.path.join(tmpdir, "scripts")
            os.mkdir(scripts_dir)
            subprocess.run(["bsdcpio", "-i", "--quiet"],
                           input=gzip.GzipFile(fileobj=io.BytesIO(scripts_arch)).read(),
                           cwd=scripts_dir, check=True, capture_output=True)
            scripts = {}
            for name in ("preinstall", "postinstall"):
                with open(os.path.join(scripts_dir, name)) as f:
                    scripts[name] = f.read()
            return scripts

    def _build_scripts(self, enrollment=None):
        if enrollment is None:
            enrollment = force_enrollment()
        builder = OsqueryZentralEnrollPkgBuilder(enrollment)
        _, _, package_content = builder.build()
        return self._extract_scripts(package_content)

    # osqueryd paths

    def test_osqueryd_paths_order(self):
        self.assertEqual(OSQUERYD_PATHS[0], STANDARD_PATH)
        self.assertEqual(OSQUERYD_PATHS[1], ORBIT_PATH)
        self.assertEqual(OSQUERYD_PATHS[-1], "/usr/local/bin/osqueryd")

    def test_scripts_have_no_placeholder_left(self):
        for name, content in self._build_scripts().items():
            self.assertNotIn("%", content, name)

    def test_scripts_include_all_osqueryd_paths(self):
        scripts = self._build_scripts()
        serialized_paths = " ".join(f'"{p}"' for p in OSQUERYD_PATHS)
        for name, content in scripts.items():
            self.assertIn(f"for CANDIDATE_PATH in {serialized_paths}", content, name)

    def test_preinstall_requires_an_osqueryd_if_none_included(self):
        scripts = self._build_scripts()
        self.assertIn('if [[ -z "$OSQUERYD_PATH" ]] && [[ "0" != "1" ]]', scripts["preinstall"])

    def test_preinstall_does_not_require_an_osqueryd_if_one_is_included(self):
        enrollment = force_enrollment()
        enrollment.osquery_release = "5.10.2"
        # keep a component package, the release asset is not available in the tests
        with patch.object(OsqueryZentralEnrollPkgBuilder, "get_extra_packages", return_value=[]), \
             patch.object(OsqueryZentralEnrollPkgBuilder, "get_product_archive_title", return_value=None):
            scripts = self._build_scripts(enrollment)
        self.assertIn('if [[ -z "$OSQUERYD_PATH" ]] && [[ "1" != "1" ]]', scripts["preinstall"])

    def test_postinstall_updates_the_launch_daemon_and_the_enrollment_plist(self):
        postinstall = self._build_scripts()["postinstall"]
        self.assertIn(f'ZENTRAL_OSQUERY_PLIST="{LAUNCH_DAEMON_PLIST}"', postinstall)
        self.assertIn(
            '/usr/libexec/PlistBuddy -c "Set :ProgramArguments:0 $OSQUERYD_PATH" "$ZENTRAL_OSQUERY_PLIST"',
            postinstall
        )
        self.assertIn(
            '/usr/bin/plutil -replace osqueryd_path -string "$OSQUERYD_PATH" "$ENROLLMENT_PLIST"',
            postinstall
        )

    def test_no_release_no_product_archive_and_no_extra_package(self):
        builder = OsqueryZentralEnrollPkgBuilder(force_enrollment())
        self.addCleanup(builder._clean)
        self.assertIsNone(builder.get_product_archive_title())
        self.assertEqual(builder.get_extra_packages(), [])

    def test_release_product_archive_with_the_release_package(self):
        enrollment = force_enrollment()
        enrollment.osquery_release = "5.10.2"
        builder = OsqueryZentralEnrollPkgBuilder(enrollment)
        self.addCleanup(builder._clean)
        self.assertEqual(builder.get_product_archive_title(), builder.name)
        with patch("zentral.contrib.osquery.osx_package.builder.get_osquery_local_asset",
                   return_value="/fomo/osquery.pkg") as get_osquery_local_asset:
            self.assertEqual(builder.get_extra_packages(), ["/fomo/osquery.pkg"])
        get_osquery_local_asset.assert_called_once_with("5.10.2", ".pkg")

    def test_launch_daemon_constants_match_the_package(self):
        plist_path = os.path.join(OsqueryZentralEnrollPkgBuilder.build_tmpl_dir, "root",
                                  LAUNCH_DAEMON_PLIST.lstrip("/"))
        with open(plist_path, "rb") as f:
            self.assertEqual(plistlib.load(f)["Label"], LAUNCH_DAEMON_LABEL)

    # installcheck script

    def test_extra_installcheck_script(self):
        builder = OsqueryZentralEnrollPkgBuilder(force_enrollment())
        script = builder.get_extra_installcheck_script()
        self.assertIn('OSQUERYD_PATH="$($PLUTIL -extract osqueryd_path raw $ENROLLMENT_PLIST 2> /dev/null)"', script)
        self.assertIn(f'for CANDIDATE_PATH in {" ".join(chr(34) + p + chr(34) for p in OSQUERYD_PATHS)}', script)
        self.assertIn('[[ -n "$OSQUERYD_PATH" ]] && [[ "$CANDIDATE_PATH" != "$OSQUERYD_PATH" ]] && exit 0', script)
        self.assertIn(f'[[ ! -f "{LAUNCH_DAEMON_PLIST}" ]] && exit 0', script)
        self.assertIn(f'/bin/launchctl list {LAUNCH_DAEMON_LABEL} 2> /dev/null | grep -q \'"PID"\' || exit 0',
                      script)
        # the launch daemon tests only run with an osqueryd on the machine: without one the preinstall script
        # rejects the installation, and munki would report a failure on every run
        self.assertTrue(script.index('if [[ -x "$CANDIDATE_PATH" ]]') < script.index("/bin/launchctl list"))
        self.assertTrue(script.index("/bin/launchctl list") < script.index("break"))

    def test_package_info_installcheck_script_includes_the_extra_script(self):
        enrollment = force_enrollment()
        builder = OsqueryZentralEnrollPkgBuilder(enrollment)
        package_info = make_package_info(builder, FakeManifestEnrollmentPackage(), b"1234")
        installcheck_script = package_info["installcheck_script"]
        # the extra script comes before the tests of the enrollment values, and after the variables it uses
        self.assertIn(
            'PLUTIL="/usr/bin/plutil"\n'
            + builder.get_extra_installcheck_script()
            + '[[ ! -f "$ENROLLMENT_PLIST" ]] && exit 0\n',
            installcheck_script
        )


class FakeManifestEnrollmentPackage:
    def get_name(self):
        return "test"

    def get_requires(self):
        return []

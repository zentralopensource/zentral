from unittest import TestCase
from zentral.contrib.inventory.conf import windows_version_from_build, cleanup_windows_os_version, os_version_display


class WindowsBuildTestCase(TestCase):
    def test_from_build_bad_build_number(self):
        with self.assertRaises(ValueError) as cm:
            windows_version_from_build("abc.123")
        self.assertEqual(cm.exception.args[0], "Bad build number")

    def test_from_build_unknown_build_number(self):
        with self.assertRaises(ValueError) as cm:
            windows_version_from_build("123")
        self.assertEqual(cm.exception.args[0], "Unknown build number")

    def test_from_build_ok(self):
        for build, (major, version), display in (("19044", (10, "21H2"), "Windows 10 21H2 (19044)"),
                                                 ("19043.1682", (10, "21H1"), "Windows 10 21H1 (19043.1682)"),
                                                 ("22000.652", (11, "21H2"), "Windows 11 21H2 (22000.652)")):
            os_version_d = windows_version_from_build(build)
            self.assertEqual(os_version_d,
                             {"name": f"Windows {major}",
                              "major": major,
                              "version": version,
                              "build": build})
            self.assertEqual(os_version_display(os_version_d), display)

    def test_cleanup_patch_is_known_build(self):
        self.assertEqual(
            cleanup_windows_os_version({"major": 10, "minor": 0, "patch": 19044}),
            {"name": "Windows 10",
             "major": 10,
             "version": "21H2",
             "build": "19044"}
        )

    def test_cleanup_patch_unkown_11_build(self):
        self.assertEqual(
            cleanup_windows_os_version({"major": 10, "minor": 0, "patch": 22001}),
            {"name": "Windows 11",
             "major": 11,
             "build": "22001"}
        )

    def test_cleanup_patch_unkown_10_build_with_build(self):
        self.assertEqual(
            cleanup_windows_os_version({"major": 10, "minor": 0, "patch": 10001, "build": "123"}),
            {"name": "Windows 10",
             "major": 10,
             "build": "10001.123"}
        )

    def test_cleanup_unknown(self):
        self.assertEqual(
            cleanup_windows_os_version({"major": 9, "minor": 0, "patch": 11}),
            {"name": "Windows",
             "major": 9,
             "minor": 0,
             "build": "11"}
        )

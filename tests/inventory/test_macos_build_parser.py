from unittest import TestCase
from zentral.contrib.inventory.conf import (is_apple_os, macos_version_from_build,
                                            os_version_display, os_version_version_display)


class MacOSBuildTestCase(TestCase):
    def test_wrong_errors(self):
        for build in ("A", "", "9"):
            with self.assertRaises(ValueError) as cm:
                macos_version_from_build(build)
            self.assertEqual(cm.exception.args[0], "Bad build number")

    def test_too_old_errors(self):
        for build in ("11G56", "9A581"):
            with self.assertRaises(ValueError) as cm:
                macos_version_from_build(build)
            self.assertEqual(cm.exception.args[0], "Cannot parse build str for macos < 10.8")

    def test_ok(self):
        for build, (name, major, minor, patch, version), display in (
           ("12E4022", ("OS X", 10, 8, 4, None), "OS X 10.8.4 (12E4022)"),
           ("15G31", ("OS X", 10, 11, 6, None), "OS X 10.11.6 (15G31)"),
           ("19A471t", ("macOS", 10, 15, 0, None), "macOS 10.15 (19A471t)"),
           ("19D76", ("macOS", 10, 15, 3, None), "macOS 10.15.3 (19D76)"),
           ("20A2411", ("macOS", 11, 0, 0, None), "macOS 11.0 (20A2411)"),
           ("20B29", ("macOS", 11, 0, 1, None), "macOS 11.0.1 (20B29)"),
           ("20B50", ("macOS", 11, 0, 1, None), "macOS 11.0.1 (20B50)"),
           ("20C69", ("macOS", 11, 1, 0, None), "macOS 11.1 (20C69)"),
           ("20D74", ("macOS", 11, 2, 1, None), "macOS 11.2.1 (20D74)"),
           ("20D80", ("macOS", 11, 2, 2, None), "macOS 11.2.2 (20D80)"),
           ("20D91", ("macOS", 11, 2, 3, None), "macOS 11.2.3 (20D91)"),
           ("20G95", ("macOS", 11, 5, 2, None), "macOS 11.5.2 (20G95)"),
           ("20G165", ("macOS", 11, 6, 0, None), "macOS 11.6 (20G165)"),
           ("20G224", ("macOS", 11, 6, 1, None), "macOS 11.6.1 (20G224)"),
           ("20G314", ("macOS", 11, 6, 2, None), "macOS 11.6.2 (20G314)"),
           ("20G415", ("macOS", 11, 6, 3, None), "macOS 11.6.3 (20G415)"),
           ("20G417", ("macOS", 11, 6, 4, None), "macOS 11.6.4 (20G417)"),
           ("20G527", ("macOS", 11, 6, 5, None), "macOS 11.6.5 (20G527)"),
           ("20G624", ("macOS", 11, 6, 6, None), "macOS 11.6.6 (20G624)"),
           ("20G630", ("macOS", 11, 6, 7, None), "macOS 11.6.7 (20G630)"),
           ("20G730", ("macOS", 11, 6, 8, None), "macOS 11.6.8 (20G730)"),
           ("21A5522h", ("macOS", 12, 0, 0, None), "macOS 12.0 (21A5522h)"),
           ("21A558", ("macOS", 12, 0, 1, None), "macOS 12.0.1 (21A558)"),
           ("21C5021h", ("macOS", 12, 1, 0, None), "macOS 12.1 (21C5021h)"),
           ("21D62", ("macOS", 12, 2, 1, None), "macOS 12.2.1 (21D62)"),
           ("21E5212f", ("macOS", 12, 3, 0, None), "macOS 12.3 (21E5212f)"),
           ("21E258", ("macOS", 12, 3, 1, None), "macOS 12.3.1 (21E258)"),
           ("22A5266r", ("macOS", 13, 0, 0, None), "macOS 13.0 (22A5266r)"),
           ("21G83", ("macOS", 12, 5, 1, None), "macOS 12.5.1 (21G83)"),
           ("21G115", ("macOS", 12, 6, 0, None), "macOS 12.6 (21G115)"),
           ("20G817", ("macOS", 11, 7, 0, None), "macOS 11.7 (20G817)"),
           ("20G918", ("macOS", 11, 7, 1, None), "macOS 11.7.1 (20G918)"),
           ("20G1008", ("macOS", 11, 7, 2, None), "macOS 11.7.2 (20G1008)"),
           ("20G1020", ("macOS", 11, 7, 2, None), "macOS 11.7.2 (20G1020)"),
           ("20G1116", ("macOS", 11, 7, 3, None), "macOS 11.7.3 (20G1116)"),
           ("21G217", ("macOS", 12, 6, 1, None), "macOS 12.6.1 (21G217)"),
           ("21G309", ("macOS", 12, 6, 2, None), "macOS 12.6.2 (21G309)"),
           ("21G320", ("macOS", 12, 6, 2, None), "macOS 12.6.2 (21G320)"),
           ("21G417", ("macOS", 12, 6, 3, None), "macOS 12.6.3 (21G417)"),
           ("21G419", ("macOS", 12, 6, 3, None), "macOS 12.6.3 (21G419)"),
           ("22A400", ("macOS", 13, 0, 1, None), "macOS 13.0.1 (22A400)"),
           ("22D68", ("macOS", 13, 2, 1, None), "macOS 13.2.1 (22D68)"),
           ("22E261", ("macOS", 13, 3, 1, None), "macOS 13.3.1 (22E261)"),
           ("22E772610a", ("macOS", 13, 3, 1, "(a)"), "macOS 13.3.1 (a) (22E772610a)"),
           ("22F82", ("macOS", 13, 4, 1, None), "macOS 13.4.1 (22F82)"),
        ):
            expected_version_d = {
                "name": name,
                "major": major,
                "minor": minor,
                "patch": patch,
                "build": build
            }
            if version:
                expected_version_d["version"] = version
            parsed_version_d = macos_version_from_build(build)
            self.assertEqual(parsed_version_d, expected_version_d)
            self.assertEqual(os_version_display(parsed_version_d), display)

    def test_is_apple_os(self):
        for os_name, result in (("mACos Beta", True),
                                ("OS X", True),
                                ("iOS", True),
                                ("iPadOS", True),
                                ("tvOS", True),
                                ("watchOS", True),
                                ("", False),
                                (None, False),
                                ("Windows", False)):
            self.assertEqual(is_apple_os(os_name), result)

    def test_os_version_version_display(self):
        for os_version_d, result in (({"name": "", "major": 10, "minor": 10, "patch": 0}, "10.10.0"),
                                     ({"name": "MacOs", "major": 10, "minor": 10, "patch": 0}, "10.10"),
                                     ({"name": "MacOs", "major": 10, "minor": 10, "patch": 1}, "10.10.1")):
            self.assertEqual(os_version_version_display(os_version_d), result)

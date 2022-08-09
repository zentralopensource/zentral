from unittest import TestCase
from zentral.contrib.inventory.conf import macos_version_from_build, os_version_display


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
        for build, (name, major, minor, patch), display in (
           ("12E4022", ("OS X", 10, 8, 4), "OS X 10.8.4 (12E4022)"),
           ("15G31", ("OS X", 10, 11, 6), "OS X 10.11.6 (15G31)"),
           ("19A471t", ("macOS", 10, 15, 0), "macOS 10.15.0 (19A471t)"),
           ("19D76", ("macOS", 10, 15, 3), "macOS 10.15.3 (19D76)"),
           ("20A2411", ("macOS", 11, 0, None), "macOS 11.0 (20A2411)"),
           ("20B29", ("macOS", 11, 0, 1), "macOS 11.0.1 (20B29)"),
           ("20B50", ("macOS", 11, 0, 1), "macOS 11.0.1 (20B50)"),
           ("20C69", ("macOS", 11, 1, None), "macOS 11.1 (20C69)"),
           ("20D74", ("macOS", 11, 2, 1), "macOS 11.2.1 (20D74)"),
           ("20D80", ("macOS", 11, 2, 2), "macOS 11.2.2 (20D80)"),
           ("20D91", ("macOS", 11, 2, 3), "macOS 11.2.3 (20D91)"),
           ("20G95", ("macOS", 11, 5, 2), "macOS 11.5.2 (20G95)"),
           ("20G165", ("macOS", 11, 6, None), "macOS 11.6 (20G165)"),
           ("20G224", ("macOS", 11, 6, 1), "macOS 11.6.1 (20G224)"),
           ("20G314", ("macOS", 11, 6, 2), "macOS 11.6.2 (20G314)"),
           ("20G415", ("macOS", 11, 6, 3), "macOS 11.6.3 (20G415)"),
           ("20G417", ("macOS", 11, 6, 4), "macOS 11.6.4 (20G417)"),
           ("20G527", ("macOS", 11, 6, 5), "macOS 11.6.5 (20G527)"),
           ("20G624", ("macOS", 11, 6, 6), "macOS 11.6.6 (20G624)"),
           ("20G630", ("macOS", 11, 6, 7), "macOS 11.6.7 (20G630)"),
           ("20G730", ("macOS", 11, 6, 8), "macOS 11.6.8 (20G730)"),
           ("21A5522h", ("macOS Beta", 12, 0, None), "macOS Beta 12.0 (21A5522h)"),
           ("21A558", ("macOS", 12, 0, 1), "macOS 12.0.1 (21A558)"),
           ("21C5021h", ("macOS Beta", 12, 1, None), "macOS Beta 12.1 (21C5021h)"),
           ("21D62", ("macOS", 12, 2, 1), "macOS 12.2.1 (21D62)"),
           ("21E5212f", ("macOS Beta", 12, 3, None), "macOS Beta 12.3 (21E5212f)"),
           ("21E258", ("macOS", 12, 3, 1), "macOS 12.3.1 (21E258)"),
           ("22A5266r", ("macOS Beta", 13, 0, None), "macOS Beta 13.0 (22A5266r)")
        ):
            version_d = macos_version_from_build(build)
            self.assertEqual(version_d,
                             {"name": name,
                              "major": major,
                              "minor": minor,
                              "patch": patch,
                              "build": build})
            self.assertEqual(os_version_display(version_d), display)

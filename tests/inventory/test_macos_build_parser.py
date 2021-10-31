from unittest import TestCase
from zentral.contrib.inventory.conf import macos_version_from_build


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
        for build, (name, major, minor, patch) in (("12E4022", ("OS X", 10, 8, 4)),
                                                   ("15G31", ("OS X", 10, 11, 6)),
                                                   ("19A471t", ("macOS", 10, 15, 0)),
                                                   ("19D76", ("macOS", 10, 15, 3)),
                                                   ("20A2411", ("macOS", 11, 0, 0)),
                                                   ("20B29", ("macOS", 11, 0, 1)),
                                                   ("20B50", ("macOS", 11, 0, 1)),
                                                   ("20C69", ("macOS", 11, 1, 0)),
                                                   ("20D74", ("macOS", 11, 2, 1)),
                                                   ("20D80", ("macOS", 11, 2, 2)),
                                                   ("20D91", ("macOS", 11, 2, 3)),
                                                   ("20G95", ("macOS", 11, 5, 2)),
                                                   ("20G165", ("macOS", 11, 6, 0)),
                                                   ("21A5522h", ("macOS Beta", 12, 0, 0)),
                                                   ("21A558", ("macOS", 12, 0, 1)),
                                                   ("21C5021h", ("macOS Beta", 12, 1, 0))):
            self.assertEqual(macos_version_from_build(build),
                             {"name": name,
                              "major": major,
                              "minor": minor,
                              "patch": patch,
                              "build": build})

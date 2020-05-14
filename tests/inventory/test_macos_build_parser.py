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
        for build, (name, minor, patch) in (("12E4022", ("OS X", 8, 4)),
                                            ("15G31", ("OS X", 11, 6)),
                                            ("19A471t", ("macOS", 15, 0)),
                                            ("19D76", ("macOS", 15, 3))):
            self.assertEqual(macos_version_from_build(build),
                             {"name": name,
                              "major": 10,
                              "minor": minor,
                              "patch": patch,
                              "build": build})

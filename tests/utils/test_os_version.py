from django.test import SimpleTestCase
from zentral.utils.os_version import make_comparable_os_version


class OSVersionUtilsTestCase(SimpleTestCase):
    def test_make_comparable_os_version_major_minor(self):
        self.assertEqual(
            make_comparable_os_version("12.3"),
            (12, 3, 0)
        )

    def test_make_comparable_os_version_major_minor_patch(self):
        self.assertEqual(
            make_comparable_os_version("12.3.1"),
            (12, 3, 1)
        )

    def test_make_comparable_os_version_major_minor_supplemental(self):
        self.assertEqual(
            make_comparable_os_version("12.3 (a)"),
            (12, 3, 0, "a")
        )

    def test_make_comparable_os_version_major_minor_patch_supplemental(self):
        self.assertEqual(
            make_comparable_os_version("12.3.1  (a)"),  # double-space OK
            (12, 3, 1, "a")
        )

    def test_make_comparable_os_version_error(self):
        self.assertEqual(
            make_comparable_os_version("abc"),
            (0, 0, 0)
        )

from django.test import SimpleTestCase
from zentral.utils.os_version import (comparable_os_version_in_range, make_comparable_os_version,
                                      os_version_in_range, validate_os_version_bound, validate_os_version_range)


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
            (12, 3, 0, "(a)")
        )

    def test_make_comparable_os_version_major_minor_patch_supplemental(self):
        self.assertEqual(
            make_comparable_os_version("12.3.1  (a)"),  # double-space OK
            (12, 3, 1, "(a)")
        )

    def test_make_comparable_os_version_error(self):
        self.assertEqual(
            make_comparable_os_version("abc"),
            (0, 0, 0)
        )

    # comparable_os_version_in_range

    def test_comparable_os_version_in_range_no_bounds(self):
        self.assertTrue(comparable_os_version_in_range((0, 0, 0)))

    def test_comparable_os_version_in_range_min_inclusive(self):
        self.assertTrue(comparable_os_version_in_range((26, 0, 0), [26, 0, 0]))
        self.assertFalse(comparable_os_version_in_range((25, 9, 9), [26, 0, 0]))

    def test_comparable_os_version_in_range_max_exclusive(self):
        self.assertTrue(comparable_os_version_in_range((26, 9, 9), None, [27, 0, 0]))
        self.assertFalse(comparable_os_version_in_range((27, 0, 0), None, [27, 0, 0]))

    # os_version_in_range

    def test_os_version_in_range_no_bounds_unknown_version(self):
        self.assertTrue(os_version_in_range(None))
        self.assertTrue(os_version_in_range("yolo"))

    def test_os_version_in_range_unknown_version_never_matches_a_bound(self):
        self.assertFalse(os_version_in_range(None, max_os_version="27"))
        self.assertFalse(os_version_in_range("", max_os_version="27"))
        self.assertFalse(os_version_in_range("yolo", max_os_version="27"))

    def test_os_version_in_range(self):
        self.assertTrue(os_version_in_range("26.1", "26", "27"))
        self.assertTrue(os_version_in_range("26", "26", "27"))
        self.assertFalse(os_version_in_range("27", "26", "27"))
        self.assertFalse(os_version_in_range("25.7.1", "26", "27"))
        self.assertTrue(os_version_in_range("26.1.1", "26.1", "26.2"))

    # validate_os_version_bound

    def test_validate_os_version_bound_ok(self):
        for os_version in ("", None, "26", "26.1", "26.1.2"):
            validate_os_version_bound(os_version)

    def test_validate_os_version_bound_four_components(self):
        with self.assertRaises(ValueError) as cm:
            validate_os_version_bound("26.1.0.1")
        self.assertEqual(str(cm.exception), "An OS version has at most three components")

    def test_validate_os_version_bound_extra(self):
        with self.assertRaises(ValueError) as cm:
            validate_os_version_bound("26.3.1 (a)")
        self.assertEqual(str(cm.exception), "A supplemental OS version extra is not supported")

    def test_validate_os_version_bound_invalid(self):
        with self.assertRaises(ValueError) as cm:
            validate_os_version_bound("yolo")
        self.assertEqual(str(cm.exception), "Not a valid OS version")

    # validate_os_version_range

    def test_validate_os_version_range_ok(self):
        validate_os_version_range("", "")
        validate_os_version_range("26", "")
        validate_os_version_range("", "27")
        validate_os_version_range("26", "27")
        validate_os_version_range("26.1", "26.1.1")

    def test_validate_os_version_range_error(self):
        for min_os_version, max_os_version in (("26", "26"), ("26.1", "26"), ("27", "26.4")):
            with self.assertRaises(ValueError) as cm:
                validate_os_version_range(min_os_version, max_os_version)
            self.assertEqual(str(cm.exception), "Must be greater than the minimum OS version")

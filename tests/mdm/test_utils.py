from django.test import TestCase
from zentral.contrib.mdm.models import Platform
from zentral.contrib.mdm.utils import platform_and_os_from_machine_info


class MDMUtilsTestCase(TestCase):
    # platform_and_os_from_machine_info

    def test_platform_and_os_from_machine_info_missing_product(self):
        platform, comparable_os_version = platform_and_os_from_machine_info(
            {"OS_VERSION": "15.6.1"}
        )
        self.assertIsNone(platform)
        self.assertEqual(comparable_os_version, (15, 6, 1))

    def test_platform_and_os_from_machine_info_unknown_product(self):
        platform, comparable_os_version = platform_and_os_from_machine_info(
            {"PRODUCT": "YOLO", "OS_VERSION": "15.6.1"}
        )
        self.assertIsNone(platform)
        self.assertEqual(comparable_os_version, (15, 6, 1))

    def test_platform_and_os_from_machine_info_missing_os_version(self):
        platform, comparable_os_version = platform_and_os_from_machine_info(
            {"PRODUCT": "Mac14,2"}
        )
        self.assertTrue(platform is Platform.MACOS)
        self.assertEqual(comparable_os_version, (0,))

    def test_platform_and_os_from_machine_info_bad_os_version(self):
        platform, comparable_os_version = platform_and_os_from_machine_info(
            {"PRODUCT": "iPad13,17", "OS_VERSION": "abc"}
        )
        self.assertTrue(platform is Platform.IPADOS)
        self.assertEqual(comparable_os_version, (0,))

    def test_platform_and_os_from_machine_info_tvos(self):
        platform, comparable_os_version = platform_and_os_from_machine_info(
            {"PRODUCT": "AppleTV14,1", "OS_VERSION": "18.6"}
        )
        self.assertTrue(platform is Platform.TVOS)
        self.assertEqual(comparable_os_version, (18, 6))

    def test_platform_and_os_from_machine_info_ios(self):
        platform, comparable_os_version = platform_and_os_from_machine_info(
            {"PRODUCT": "iPhone14,7", "OS_VERSION": "18.6.2"}
        )
        self.assertTrue(platform is Platform.IOS)
        self.assertEqual(comparable_os_version, (18, 6, 2))

    def test_platform_and_os_from_machine_info_macos_build_fallback(self):
        platform, comparable_os_version = platform_and_os_from_machine_info(
            {"PRODUCT": "Mac14,2", "OS_VERSION": "", "VERSION": "24G90"}
        )
        self.assertTrue(platform is Platform.MACOS)
        self.assertEqual(comparable_os_version, (15, 6, 1))

    def test_platform_and_os_from_machine_info_macos_build_fallback_error(self):
        platform, comparable_os_version = platform_and_os_from_machine_info(
            {"PRODUCT": "Mac14,2", "VERSION": "YOLO"}
        )
        self.assertTrue(platform is Platform.MACOS)
        self.assertEqual(comparable_os_version, (0,))

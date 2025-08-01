from django.test import TestCase
from unittest.mock import patch
from zentral.contrib.inventory.events import InventoryCleanupFinished, InventoryCleanupStarted
from zentral.contrib.inventory.tasks import (cleanup_inventory,
                                             # inventory
                                             export_inventory,
                                             export_full_inventory,
                                             # apps
                                             export_android_apps,
                                             export_deb_packages,
                                             export_ios_apps,
                                             export_macos_apps,
                                             export_programs,
                                             # machine apps
                                             export_machine_android_apps,
                                             export_machine_deb_packages,
                                             export_machine_ios_apps,
                                             export_machine_macos_app_instances,
                                             export_machine_program_instances,
                                             # machine snapshots
                                             export_machine_snapshots)
from .utils import create_ms


class InventoryTasksTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.ms = create_ms()

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_cleanup_inventory(self, post_event):
        result = cleanup_inventory(17, {})
        self.assertTrue(all(tr["status"] == 0 for tr in result["tables"].values()))
        self.assertEqual(result["days"], 17)
        self.assertEqual(len(post_event.call_args_list), 2)
        first_event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(first_event, InventoryCleanupStarted)
        self.assertEqual(first_event.payload["cleanup"]["days"], 17)
        second_event = post_event.call_args_list[1].args[0]
        self.assertIsInstance(second_event, InventoryCleanupFinished)
        self.assertEqual(second_event.payload["cleanup"]["days"], 17)

    # inventory

    def test_export_inventory_zip(self):
        result = export_inventory("", "yolo_inv.zip")
        self.assertEqual(result["filepath"], "exports/yolo_inv.zip")

    def test_export_inventory_xlsx(self):
        result = export_inventory("", "yolo_inv.xlsx")
        self.assertEqual(result["filepath"], "exports/yolo_inv.xlsx")

    def test_export_full_inventory(self):
        result = export_full_inventory()
        self.assertTrue(result["filepath"].startswith("exports/full_inventory_export-2"))

    # apps

    def test_export_android_apps(self):
        result = export_android_apps({}, "yolo_android.csv")
        self.assertEqual(result["filepath"], "exports/yolo_android.csv")

    def test_export_deb_packages(self):
        result = export_deb_packages({}, "yolo_deb.xlsx")
        self.assertEqual(result["filepath"], "exports/yolo_deb.xlsx")

    def test_export_ios_apps(self):
        result = export_ios_apps({}, "yolo_ios.csv")
        self.assertEqual(result["filepath"], "exports/yolo_ios.csv")

    def test_export_macos_apps(self):
        result = export_macos_apps({}, "yolo_macos.xlsx")
        self.assertEqual(result["filepath"], "exports/yolo_macos.xlsx")

    def test_export_programs(self):
        result = export_programs({}, "yolo_programs.csv")
        self.assertEqual(result["filepath"], "exports/yolo_programs.csv")

    def test_export_apps_unknown_file_ext(self):
        with self.assertRaises(ValueError) as cm:
            export_programs({}, "yolo.fomo")
        self.assertEqual(cm.exception.args[0], "Unknown file extension '.fomo'")

    # machine apps

    def test_export_machine_android_apps(self):
        result = export_machine_android_apps()
        self.assertTrue(result["filepath"].startswith("exports/inventory_machine_android_apps_export"))

    def test_export_machine_deb_packages(self):
        result = export_machine_deb_packages()
        self.assertTrue(result["filepath"].startswith("exports/inventory_machine_deb_packages_export"))

    def test_export_machine_ios_apps(self):
        result = export_machine_ios_apps()
        self.assertTrue(result["filepath"].startswith("exports/inventory_machine_ios_apps_export"))

    def test_export_machine_macos_app_instances(self):
        result = export_machine_macos_app_instances()
        self.assertTrue(result["filepath"].startswith("exports/inventory_machine_macos_app_instances_export"))

    def test_export_machine_program_instances(self):
        result = export_machine_program_instances()
        self.assertTrue(result["filepath"].startswith("exports/inventory_machine_program_instances_export"))

    # machine snapshots

    def test_export_machine_snapshots(self):
        result = export_machine_snapshots()
        self.assertTrue(result["filepath"].startswith("exports/machine_snapshots-"))

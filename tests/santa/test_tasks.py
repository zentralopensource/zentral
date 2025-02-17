from django.test import TestCase
from django.utils.crypto import get_random_string
from .utils import add_file_to_test_class
from zentral.contrib.santa.models import Target
from zentral.contrib.santa.tasks import _export_targets, _iter_targets


class SantaTasksTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        add_file_to_test_class(cls)

    def test_iter_targets_search_file_sha256(self):
        targets = list(_iter_targets({"q": self.file_sha256}))
        self.assertEqual(len(targets), 1)
        target_type, row = targets[0]
        self.assertEqual(target_type, Target.Type.BINARY)
        for field, val in row:
            if field == "identifier":
                self.assertEqual(val, self.file_sha256)
                break
        else:
            raise AssertionError("Identifier not found")

    def test_export_zip(self):
        self.assertEqual(
            _export_targets({}, "zip", "yolo.zip"),
            {'filepath': 'exports/yolo.zip',
             'headers': {'Content-Disposition': 'attachment; filename="yolo.zip"',
                         'Content-Type': 'application/zip'}}
        )

    def test_export_empty_zip(self):
        self.assertEqual(
            _export_targets({"q": get_random_string(12)}, "zip", "yolo.zip"),
            {'filepath': 'exports/yolo.zip',
             'headers': {'Content-Disposition': 'attachment; filename="yolo.zip"',
                         'Content-Type': 'application/zip'}}
        )

    def test_export_xlsx(self):
        self.assertEqual(
            _export_targets({}, "xlsx", "yolo.xlsx"),
            {'filepath': 'exports/yolo.xlsx',
             'headers': {'Content-Disposition': 'attachment; filename="yolo.xlsx"',
                         'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}}
        )

    def test_export_empty_xlsx(self):
        self.assertEqual(
            _export_targets({"q": get_random_string(12)}, "xlsx", "yolo.xlsx"),
            {'filepath': 'exports/yolo.xlsx',
             'headers': {'Content-Disposition': 'attachment; filename="yolo.xlsx"',
                         'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}}
        )

    def test_export_unsupported_format(self):
        with self.assertRaises(ValueError) as cm:
            _export_targets({}, "fomo", "yolo.fomo")
        self.assertEqual(cm.exception.args[0], "Unsupported export format")

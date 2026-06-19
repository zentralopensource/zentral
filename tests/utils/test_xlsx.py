import io
import xlsxwriter
from django.test import SimpleTestCase
from zentral.utils.xlsx import add_worksheet, MAX_WORKSHEET_NAME_LENGTH, _safe_worksheet_name


INVALID_CHARS = "[]:*?/\\"


class XLSXWorksheetNameTestCase(SimpleTestCase):
    def test_plain_name_unchanged(self):
        self.assertEqual(_safe_worksheet_name("Machines"), "Machines")

    def test_invalid_chars_replaced(self):
        for raw in ("a[b]c", "a:b", "a*b", "a?b", "a/b", "a\\b"):
            name = _safe_worksheet_name(raw)
            self.assertFalse(any(c in name for c in INVALID_CHARS))

    def test_invalid_chars_become_single_space(self):
        self.assertEqual(_safe_worksheet_name("Disk: encrypted"), "Disk encrypted")
        self.assertEqual(_safe_worksheet_name("QA/Prod"), "QA Prod")

    def test_whitespace_collapsed_and_stripped(self):
        self.assertEqual(_safe_worksheet_name("  a\t b\n "), "a b")

    def test_truncated_to_31_chars(self):
        self.assertLessEqual(len(_safe_worksheet_name("x" * 50)), MAX_WORKSHEET_NAME_LENGTH)

    def test_leading_trailing_apostrophes_stripped(self):
        self.assertEqual(_safe_worksheet_name("'wat'"), "wat")

    def test_inner_apostrophe_kept(self):
        self.assertEqual(_safe_worksheet_name("a'b"), "a'b")

    def test_empty_result_falls_back_to_sheet(self):
        for raw in ("", "''", "[]:*", "   "):
            self.assertEqual(_safe_worksheet_name(raw), "Sheet")

    def test_no_used_names_does_not_dedup(self):
        self.assertEqual(_safe_worksheet_name("Tags"), "Tags")
        self.assertEqual(_safe_worksheet_name("Tags"), "Tags")

    def test_dedup_case_insensitive(self):
        used = set()
        self.assertEqual(_safe_worksheet_name("Tags", used), "Tags")
        self.assertEqual(_safe_worksheet_name("tags", used), "tags (2)")
        self.assertEqual(_safe_worksheet_name("TAGS", used), "TAGS (3)")

    def test_dedup_collision_after_truncation_stays_within_limit(self):
        used = set()
        first = _safe_worksheet_name("Acme Corporation Engineering Dept A", used)
        second = _safe_worksheet_name("Acme Corporation Engineering Dept B", used)
        self.assertNotEqual(first.lower(), second.lower())
        self.assertLessEqual(len(first), MAX_WORKSHEET_NAME_LENGTH)
        self.assertLessEqual(len(second), MAX_WORKSHEET_NAME_LENGTH)

    def test_add_worksheet_accepts_every_nasty_name(self):
        # Cross-check against the pinned library through the real wrapper:
        # xlsxwriter's add_worksheet runs its own _check_sheetname and raises
        # InvalidWorksheetName / DuplicateWorksheetName on anything we missed,
        # and the wrapper must dedup using the workbook's own sheet names.
        nasty = [
            "Tags - QA/Prod:[2024]*?",
            "Tags - QA\\Prod",
            "'leading and trailing'",
            "x" * 60,
            "x" * 60,             # collides with the previous entry
            "Disk: encrypted",
            "disk: encrypted",    # case-insensitive collision
            INVALID_CHARS,        # everything invalid -> "Sheet"
            "",                   # empty -> "Sheet" (collides)
        ]
        workbook = xlsxwriter.Workbook(io.BytesIO(), {"in_memory": True})
        for raw in nasty:
            add_worksheet(workbook, raw)
        names = [ws.name for ws in workbook.worksheets()]
        workbook.close()
        self.assertEqual(len(names), len(nasty))
        self.assertEqual(len(names), len({n.lower() for n in names}))
        for name in names:
            self.assertTrue(0 < len(name) <= MAX_WORKSHEET_NAME_LENGTH)
            self.assertFalse(any(c in name for c in INVALID_CHARS))
            self.assertFalse(name.startswith("'") or name.endswith("'"))

from collections import namedtuple
from datetime import date, datetime
import io
import uuid
from django.test import SimpleTestCase
from zentral.utils.csv import STR_OIDS, TEXT_CONVERTERS, iter_csv_parts, text_converters, text_row
from zentral.utils.parquet import ARROW_TYPES


Column = namedtuple("Column", "name type_code")


class CSVTestCase(SimpleTestCase):
    def test_text_row(self):
        description = [Column("id", 23), Column("name", 25), Column("facts", 3802), Column("config", 114),
                       Column("uuid", 2950), Column("ts", 1114), Column("ip", 869), Column("day", 1082),
                       Column("ok", 16), Column("ko", 16)]
        row = (1, "yolo", '{"un": 1}', {"deux": 2}, uuid.UUID(int=1), datetime(2026, 9, 11, 10),
               "203.0.113.1", date(2026, 9, 11), True, False)
        self.assertEqual(
            text_row(text_converters(description), row),
            # JSON values are text, naive UTC timestamps are marked UTC, booleans are true and false
            ["1", "yolo", '{"un": 1}', '{"deux": 2}', "00000000-0000-0000-0000-000000000001",
             "2026-09-11T10:00:00Z", "203.0.113.1", "2026-09-11", "true", "false"]
        )

    def test_text_row_parsed_jsonb(self):
        # a jsonb value reaches the cursor as text or as a parsed object
        self.assertEqual(text_row(text_converters([Column("facts", 3802)]), ({"un": 1},)), ['{"un": 1}'])

    def test_text_row_null(self):
        description = [Column("id", 23), Column("ts", 1114), Column("ok", 16), Column("facts", 3802)]
        # a NULL stays a NULL, the writer gives it an empty field
        self.assertEqual(text_row(text_converters(description), (None, None, None, None)), [None, None, None, None])

    def test_text_converters_unknown_oid(self):
        with self.assertRaises(ValueError) as cm:
            text_converters([Column("amount", 1700)])
        self.assertEqual(cm.exception.args[0], "Unknown PostgreSQL type OID 1700 for column amount")

    def test_text_converters_cover_the_arrow_types(self):
        # a type the Parquet export knows cannot make the CSV export raise during an export
        self.assertEqual(STR_OIDS | set(TEXT_CONVERTERS), set(ARROW_TYPES))

    def _iter_parts(self, rows, max_part_size):
        description = [Column("id", 23), Column("name", 25)]
        batches = ([(i, f"name {i}")] for i in range(rows))
        parts = []
        for index, part_rows, sink in iter_csv_parts(description, batches, lambda index: io.BytesIO(), max_part_size):
            lines = sink.getvalue().decode("utf-8").split("\n")
            # each part starts with the header, and ends with a line break
            self.assertEqual(lines[0], "id,name")
            self.assertEqual(lines[-1], "")
            parts.append((index, part_rows, len(lines) - 2))
        return parts

    def test_iter_csv_parts_rolls_the_parts(self):
        self.assertEqual(self._iter_parts(3, max_part_size=1), [(1, 1, 1), (2, 1, 1), (3, 1, 1)])

    def test_iter_csv_parts_one_part(self):
        self.assertEqual(self._iter_parts(3, max_part_size=2**20), [(1, 3, 3)])

    def test_iter_csv_parts_no_rows(self):
        # a table without a row keeps its columns in one file
        self.assertEqual(self._iter_parts(0, max_part_size=1), [(1, 0, 0)])

    def test_iter_csv_parts_quoting(self):
        description = [Column("name", 25), Column("empty", 25), Column("null", 25)]
        batches = iter([[('comma, "quote"\nnewline', "", None)]])
        (_, _, sink), = iter_csv_parts(description, batches, lambda index: io.BytesIO(), 2**20)
        # RFC 4180 quoting, and an empty field for an empty string as well as for a NULL
        self.assertEqual(sink.getvalue().decode("utf-8"),
                         'name,empty,null\n"comma, ""quote""\nnewline",,\n')

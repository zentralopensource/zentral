from collections import namedtuple
from datetime import datetime
import io
import uuid
import pyarrow.parquet as pq
from django.test import SimpleTestCase
from zentral.utils.parquet import arrow_schema, iter_parquet_parts, record_batch


Column = namedtuple("Column", "name type_code")


class ParquetTestCase(SimpleTestCase):
    def test_arrow_schema(self):
        schema = arrow_schema([Column("id", 23), Column("name", 25),
                               Column("created_at", 1114), Column("facts", 3802)])
        self.assertEqual(
            [(field.name, str(field.type), field.nullable) for field in schema],
            [("id", "int32", True),
             ("name", "string", True),
             ("created_at", "timestamp[us, tz=UTC]", True),
             ("facts", "string", True)]
        )

    def test_arrow_schema_unknown_oid(self):
        with self.assertRaises(ValueError) as cm:
            arrow_schema([Column("amount", 1700)])
        self.assertEqual(cm.exception.args[0], "Unknown PostgreSQL type OID 1700 for column amount")

    def test_record_batch(self):
        description = [Column("id", 23), Column("facts", 3802), Column("config", 114),
                       Column("uuid", 2950), Column("ts", 1114), Column("ip", 869)]
        schema = arrow_schema(description)
        rows = [(1, '{"un": 1}', {"deux": 2}, uuid.UUID(int=1), datetime(2026, 9, 11, 10), "203.0.113.1"),
                (2, {"trois": 3}, None, None, None, None),
                (3, None, None, None, None, None)]
        batch = record_batch(schema, description, rows)
        self.assertEqual(batch.num_rows, 3)
        self.assertEqual(batch.column("id").to_pylist(), [1, 2, 3])
        # JSON values are text: jsonb comes as text or as parsed values, json as parsed values
        self.assertEqual(batch.column("facts").to_pylist(), ['{"un": 1}', '{"trois": 3}', None])
        self.assertEqual(batch.column("config").to_pylist(), ['{"deux": 2}', None, None])
        self.assertEqual(batch.column("uuid").to_pylist(), ["00000000-0000-0000-0000-000000000001", None, None])
        # inet values are text
        self.assertEqual(batch.column("ip").to_pylist(), ["203.0.113.1", None, None])
        # naive UTC timestamps are marked UTC
        self.assertEqual(batch.column("ts").to_pylist()[0].isoformat(), "2026-09-11T10:00:00+00:00")
        self.assertIsNone(batch.column("ts").to_pylist()[1])

    def _iter_parts(self, rows, max_part_size):
        description = [Column("id", 23)]
        schema = arrow_schema(description)
        batches = (record_batch(schema, description, [(i,)]) for i in range(rows))
        parts = []
        for index, part_rows, sink in iter_parquet_parts(schema, batches, lambda index: io.BytesIO(), max_part_size):
            table = pq.read_table(io.BytesIO(sink.getvalue()))
            self.assertTrue(table.schema.equals(schema, check_metadata=False))
            parts.append((index, part_rows, table.num_rows))
        return parts

    def test_iter_parquet_parts_rolls_the_parts(self):
        self.assertEqual(self._iter_parts(3, max_part_size=1), [(1, 1, 1), (2, 1, 1), (3, 1, 1)])

    def test_iter_parquet_parts_one_part(self):
        self.assertEqual(self._iter_parts(3, max_part_size=2**20), [(1, 3, 3)])

    def test_iter_parquet_parts_no_rows(self):
        # a table without a row keeps its schema in one file
        self.assertEqual(self._iter_parts(0, max_part_size=1), [(1, 0, 0)])

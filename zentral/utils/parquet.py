import json
import pyarrow as pa
import pyarrow.parquet as pq


# PostgreSQL type OIDs. The timestamps are naive UTC in the database (USE_TZ = False).
ARROW_TYPES = {
    16: pa.bool_(),  # bool
    20: pa.int64(),  # int8
    21: pa.int16(),  # int2
    23: pa.int32(),  # int4
    25: pa.string(),  # text
    114: pa.string(),  # json, serialized
    700: pa.float32(),  # float4
    701: pa.float64(),  # float8
    869: pa.string(),  # inet
    1042: pa.string(),  # bpchar
    1043: pa.string(),  # varchar
    1082: pa.date32(),  # date
    1114: pa.timestamp("us", tz="UTC"),  # timestamp
    1184: pa.timestamp("us", tz="UTC"),  # timestamptz
    2950: pa.string(),  # uuid
    3802: pa.string(),  # jsonb, serialized
}


def json_text(value):
    # jsonb values reach the cursor as text, json values as parsed objects
    if isinstance(value, str):
        return value
    return json.dumps(value)


CONVERTERS = {
    114: json.dumps,
    2950: str,
    3802: json_text,
}


def arrow_schema(description):
    fields = []
    for column in description:
        try:
            arrow_type = ARROW_TYPES[column.type_code]
        except KeyError:
            raise ValueError(f"Unknown PostgreSQL type OID {column.type_code} for column {column.name}")
        fields.append(pa.field(column.name, arrow_type))
    return pa.schema(fields)


def record_batch(schema, description, rows):
    arrays = []
    for index, (field, column) in enumerate(zip(schema, description)):
        values = [row[index] for row in rows]
        converter = CONVERTERS.get(column.type_code)
        if converter:
            values = [converter(value) if value is not None else None for value in values]
        arrays.append(pa.array(values, type=field.type))
    return pa.RecordBatch.from_arrays(arrays, schema=schema)


def new_parquet_writer(sink, schema):
    return pq.ParquetWriter(sink, schema, compression="zstd", write_page_index=True)


def iter_parquet_parts(schema, batches, open_part, max_part_size):
    # yields (index, rows, sink) for each part, with the footer written and the sink still open
    writer = sink = None
    index = rows = 0
    for batch in batches:
        if writer is None:
            index += 1
            rows = 0
            sink = open_part(index)
            writer = new_parquet_writer(sink, schema)
        writer.write_batch(batch)
        rows += batch.num_rows
        if sink.tell() >= max_part_size:
            writer.close()
            yield index, rows, sink
            writer = sink = None
    if index == 0:
        # a table without a row keeps its schema in one file
        index = 1
        sink = open_part(index)
        writer = new_parquet_writer(sink, schema)
    if writer is not None:
        writer.close()
        yield index, rows, sink

import csv
import json


# PostgreSQL type OIDs, like in zentral.utils.parquet. The timestamps are naive UTC in the database
# (USE_TZ = False), and the CSV export marks them as UTC.

STR_OIDS = frozenset((
    20,  # int8
    21,  # int2
    23,  # int4
    25,  # text
    700,  # float4
    701,  # float8
    869,  # inet
    1042,  # bpchar
    1043,  # varchar
    1082,  # date
    2950,  # uuid
))


def bool_text(value):
    return "true" if value else "false"


def utc_text(value):
    return f"{value.isoformat()}Z"


def json_text(value):
    # jsonb values reach the cursor as text, json values as parsed objects
    if isinstance(value, str):
        return value
    return json.dumps(value)


TEXT_CONVERTERS = {
    16: bool_text,  # bool
    114: json.dumps,  # json
    1114: utc_text,  # timestamp
    1184: utc_text,  # timestamptz
    3802: json_text,  # jsonb
}


def text_converters(description):
    converters = []
    for column in description:
        if column.type_code in STR_OIDS:
            converters.append(str)
        else:
            try:
                converters.append(TEXT_CONVERTERS[column.type_code])
            except KeyError:
                raise ValueError(f"Unknown PostgreSQL type OID {column.type_code} for column {column.name}")
    return converters


def text_row(converters, row):
    # a None stays a None: csv.QUOTE_MINIMAL writes it as an empty field
    return [converter(value) if value is not None else None for converter, value in zip(converters, row)]


class TextSink:
    # csv.writer writes strings, the parts count and hash bytes
    def __init__(self, sink):
        self._sink = sink

    def write(self, text):
        self._sink.write(text.encode("utf-8"))


def new_csv_writer(sink, columns):
    writer = csv.writer(TextSink(sink), lineterminator="\n")
    writer.writerow(columns)
    return writer


def iter_csv_parts(description, batches, open_part, max_part_size):
    # yields (index, rows, sink) for each part, with the sink still open. Each part starts with the
    # header, so a reader opens any part on its own, and rows counts the data rows only.
    columns = [column.name for column in description]
    converters = text_converters(description)
    writer = sink = None
    index = rows = 0
    for batch in batches:
        for row in batch:
            if writer is None:
                index += 1
                rows = 0
                sink = open_part(index)
                writer = new_csv_writer(sink, columns)
            writer.writerow(text_row(converters, row))
            rows += 1
            if sink.tell() >= max_part_size:
                yield index, rows, sink
                writer = sink = None
    if index == 0:
        # a table without a row keeps its columns in one file
        index = 1
        sink = open_part(index)
        writer = new_csv_writer(sink, columns)
    if writer is not None:
        yield index, rows, sink

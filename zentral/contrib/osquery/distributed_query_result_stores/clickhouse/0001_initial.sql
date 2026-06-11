CREATE TABLE IF NOT EXISTS {database}.{table_name} (
    distributed_query_id  UInt64,
    serial_number         String,
    row_index             UInt64,
    received_at           DateTime64(6),
    row                   String
)
ENGINE = ReplacingMergeTree(received_at)
ORDER BY (distributed_query_id, serial_number, row_index)
TTL received_at + toIntervalDay({ttl_days})
SETTINGS non_replicated_deduplication_window = 1000;

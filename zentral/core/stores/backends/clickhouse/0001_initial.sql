-- Events
-- see https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/7592debad2e93652412f2cd9eb299e9ac8d169f3/exporter/clickhouseexporter/internal/sqltemplates/logs_json_table.sql

CREATE TABLE IF NOT EXISTS `{database}`.`{table_name}`
(
    `created_at` DateTime64(9, 'UTC') CODEC(Delta(8), ZSTD(1)),
    `type` LowCardinality(String) CODEC(ZSTD(1)),
    `tags` Array(LowCardinality(String)) CODEC(ZSTD(1)),
    `needles` Array(LowCardinality(String)) CODEC(ZSTD(1)),
    `serial_number` LowCardinality(String) CODEC(ZSTD(1)),
    `metadata` JSON CODEC(ZSTD(1)),
    `payload` JSON CODEC(ZSTD(1)),
    INDEX needles_idx needles TYPE bloom_filter GRANULARITY 1
)
ENGINE = {table_engine}
PARTITION BY toDate(created_at)
PRIMARY KEY (type, toDateTime(created_at))
ORDER BY (type, toDateTime(created_at), created_at)
TTL created_at + toIntervalDay({ttl_days})
SETTINGS ttl_only_drop_parts = 1;

-- Event tags aggregations

CREATE TABLE IF NOT EXISTS `{database}`.`{table_name}_tags_aggs`
(
    `date` Date,
    `tag` LowCardinality(String),
    `events` SimpleAggregateFunction(sum, UInt64),
    `machines` AggregateFunction(uniqExact, String)
)
ENGINE = AggregatingMergeTree
ORDER BY (date, tag)
TTL date + toIntervalDay(31);

CREATE MATERIALIZED VIEW IF NOT EXISTS `{database}`.`{table_name}_tags_aggs_mv` TO `{database}`.`{table_name}_tags_aggs`
AS SELECT
    date_trunc('day', created_at) AS date,
    tags AS tag,
    count(*) AS events,
    uniqExactState(serial_number) AS machines
FROM `{database}`.`{table_name}`
ARRAY JOIN tags
GROUP BY
    tag,
    date;

-- Machine heartbeats

CREATE TABLE IF NOT EXISTS `{database}`.`{table_name}_machine_heartbeats`
(
    `serial_number` LowCardinality(String),
    `type` LowCardinality(String),
    `key` LowCardinality(String),
    `last_seen` SimpleAggregateFunction(max, DateTime64(9, 'UTC'))
)
ENGINE = AggregatingMergeTree
ORDER BY (serial_number, type, key);

CREATE MATERIALIZED VIEW IF NOT EXISTS `{database}`.`{table_name}_machine_heartbeats_mv` TO `{database}`.`{table_name}_machine_heartbeats`
AS SELECT
    serial_number,
    type,
    multiIf(type = 'inventory_heartbeat', payload.source.name.:String, metadata.request.user_agent.:String) AS key,
    maxSimpleState(created_at) AS last_seen
FROM `{database}`.`{table_name}`
WHERE has(tags, 'heartbeat')
GROUP BY
    serial_number,
    type,
    key;

-- Event types machines aggregations

CREATE TABLE IF NOT EXISTS `{database}`.`{table_name}_types_needles_aggs`
(
    `needle` LowCardinality(String),
    `type` LowCardinality(String),
    `date` Date,
    `count` UInt32
)
ENGINE = SummingMergeTree
ORDER BY (needle, type, date)
TTL date + toIntervalDay(31);

CREATE MATERIALIZED VIEW IF NOT EXISTS `{database}`.`{table_name}_types_needles_aggs_mv` TO `{database}`.`{table_name}_types_needles_aggs`
AS SELECT
    needles AS needle,
    type,
    date_trunc('day', created_at) AS date,
    count(*) AS count
FROM zentral_events
ARRAY JOIN needles
GROUP BY
    needle,
    type,
    date;

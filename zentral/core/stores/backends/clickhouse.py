import logging
import clickhouse_connect
from django.utils.functional import cached_property
from rest_framework import serializers
from .base import BaseStore


logger = logging.getLogger('zentral.core.stores.backends.clickhouse')


class ClickHouseStore(BaseStore):
    client_kwargs_keys = (
        # connection
        "host",
        "port",
        "secure",
        "verify",
        "compress",
        # auth
        "username",
        "database",
        "password",
        "access_token",
        # timeouts
        "connect_timeout",
        "send_receive_timeout",
    )
    kwargs_keys = client_kwargs_keys + (
        # storage
        "table_engine",
        "table_name",
        "ttl_days",
        "batch_size",
    )
    encrypted_kwargs_paths = (
        ["password"],
        ["access_token"],
    )
    identifier_regex = r"^[a-zA-Z_][0-9a-zA-Z_]*$"
    default_batch_size = 100
    default_connect_timeout = 10
    default_database = "default"
    default_table_name = "zentral_events"
    default_send_receive_timeout = 300
    default_table_engine = "MergeTree"
    default_tls_port = 8443
    default_ttl_days = 90
    max_batch_size = 1000

    @cached_property
    def client(self):
        return clickhouse_connect.get_client(
            **{k: getattr(self, k)
               for k in self.client_kwargs_keys}
        )

    def wait_and_configure(self):
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/7592debad2e93652412f2cd9eb299e9ac8d169f3/exporter/clickhouseexporter/internal/sqltemplates/logs_json_table.sql  # NOQA
        self.client.command(
            f'CREATE TABLE IF NOT EXISTS "{self.database}"."{self.table_name}" ('
            "created_at DateTime64(9, 'UTC') CODEC(Delta(8), ZSTD(1)),"
            "type LowCardinality(String) CODEC(ZSTD(1)),"
            "tags Array(LowCardinality(String)) CODEC(ZSTD(1)),"
            "needles Array(LowCardinality(String)) CODEC(ZSTD(1)),"
            "serial_number LowCardinality(String) CODEC(ZSTD(1)),"
            "metadata JSON CODEC(ZSTD(1)),"
            "payload JSON CODEC(ZSTD(1)),"
            "INDEX needles_idx needles TYPE bloom_filter GRANULARITY 1"
            f") ENGINE = {self.table_engine} "
            "PARTITION BY toDate(created_at) "
            "PRIMARY KEY (type, toDateTime(created_at)) "
            "ORDER BY (type, toDateTime(created_at), created_at) "
            f"TTL created_at + toIntervalDay({self.ttl_days}) "
            "SETTINGS ttl_only_drop_parts = 1"
        )
        self.column_names = (
            "created_at",
            "type",
            "tags",
            "needles",
            "serial_number",
            "metadata",
            "payload",
        )
        self.configured = True

    def _serialize_event(self, event):
        if not isinstance(event, dict):
            event_d = event.serialize()
        else:
            event_d = event
        metadata = event_d.pop("_zentral")
        created_at = metadata.pop("created_at")
        event_type = metadata.pop("type")
        tags = metadata.pop("tags", [])
        needles = []  # for serial_number, object, probe lookups
        serial_number = metadata.get("machine_serial_number")
        if serial_number:
            needles.append(f"_s:{serial_number}")
        else:
            serial_number = ""
        for obj_k, obj_vals in metadata.get("objects", {}).items():
            for obj_val in obj_vals:
                needles.append(f"_o:{obj_k}:{obj_val}")
        for probe in metadata.get("probes", []):
            needles.append(f"_p:{probe['pk']}")
        payload = event_d
        return (
            # event key
            (metadata["id"], metadata["index"]),
            # tuple
            (created_at,
             event_type,
             tags,
             needles,
             serial_number,
             metadata,
             payload),
        )

    def _insert(self, data):
        self.wait_and_configure_if_necessary()
        self.client.insert(
            self.table_name,
            data,
            column_names=self.column_names,
        )

    def store(self, event):
        _, event_t = self._serialize_event(event)
        self._insert([event_t])

    def bulk_store(self, events):
        self.wait_and_configure_if_necessary()
        event_keys = []
        data = []
        for event in events:
            event_key, event_t = self._serialize_event(event)
            event_keys.append(event_key)
            data.append(event_t)
        self._insert(data)
        return event_keys


# Serializers


class ClickHouseStoreSerializer(serializers.Serializer):
    # connection
    host = serializers.CharField(min_length=1)
    port = serializers.IntegerField(
        min_value=1, max_value=65535,
        default=ClickHouseStore.default_tls_port,
        required=False
    )
    secure = serializers.BooleanField(default=True, required=False)
    verify = serializers.BooleanField(default=True, required=False)
    compress = serializers.BooleanField(default=True, required=False)
    # auth
    username = serializers.CharField(required=False, allow_null=True)
    database = serializers.RegexField(
        regex=ClickHouseStore.identifier_regex,
        required=False,
        default=ClickHouseStore.default_database
    )
    password = serializers.CharField(required=False, default="")
    access_token = serializers.CharField(required=False, allow_null=True)
    # timeouts
    connect_timeout = serializers.IntegerField(
        min_value=1,
        required=False,
        default=ClickHouseStore.default_connect_timeout
    )
    send_receive_timeout = serializers.IntegerField(
        min_value=1,
        required=False,
        default=ClickHouseStore.default_send_receive_timeout
    )
    # storage
    table_engine = serializers.RegexField(
        regex=ClickHouseStore.identifier_regex,
        required=False,
        default=ClickHouseStore.default_table_engine
    )
    table_name = serializers.RegexField(
        regex=ClickHouseStore.identifier_regex,
        required=False,
        default=ClickHouseStore.default_table_name
    )
    ttl_days = serializers.IntegerField(min_value=1, required=False, default=ClickHouseStore.default_ttl_days)
    batch_size = serializers.IntegerField(
        min_value=1, required=False,
        default=ClickHouseStore.default_batch_size,
        max_value=ClickHouseStore.max_batch_size,
    )

    def validate(self, data):
        username = data.get("username")
        password = data.get("password")
        access_token = data.get("access_token")
        if access_token and (username or password):
            raise serializers.ValidationError("Cannot use both access_token and username/password")
        return data

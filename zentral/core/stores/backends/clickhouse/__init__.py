from datetime import datetime, timedelta
import logging
import os
import clickhouse_connect
from django.utils.functional import cached_property
from django.utils.timezone import is_naive, make_aware, make_naive
from kombu.utils import json
from rest_framework import serializers
from zentral.core.events import event_from_event_d, event_types
from zentral.core.stores.backends.base import BaseStore, serialize_needles


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
    column_names = (
        "created_at",
        "type",
        "tags",
        "needles",
        "serial_number",
        "metadata",
        "payload",
    )
    machine_events = True
    last_machine_heartbeats = True
    object_events = True
    probe_events = True

    @cached_property
    def client(self):
        return clickhouse_connect.get_client(
            autogenerate_session_id=False,  # we do run queries concurrently when querying the database
            **{k: getattr(self, k)
               for k in self.client_kwargs_keys}
        )

    def migrate(self):
        # TODO: much to be done here in the future!
        migration_filepath = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "0001_initial.sql"
        )
        with open(migration_filepath) as f:
            sql = f.read()
        sql = sql.format(
            database=self.database,
            table_name=self.table_name,
            table_engine=self.table_engine,
            ttl_days=self.ttl_days,
        )
        for statement in (s.strip() for s in sql.split(";")):
            if not statement:
                continue
            self.client.command(statement)

    def wait_and_configure(self):
        self.migrate()
        super().wait_and_configure()

    def _serialize_event(self, event):
        if not isinstance(event, dict):
            event_d = event.serialize()
        else:
            event_d = event
        metadata = event_d.pop("_zentral")
        created_at = metadata.pop("created_at")
        event_type = metadata.pop("type")
        tags = metadata.pop("tags", [])
        needles = serialize_needles(metadata)
        serial_number = metadata.get("machine_serial_number") or ""
        event_key = (metadata["id"], metadata["index"])
        metadata = json.dumps(metadata)
        payload = json.dumps(event_d)
        return (
            # event key
            event_key,
            # tuple
            (created_at,
             event_type,
             tags,
             needles,
             serial_number,
             metadata,
             payload),
        )

    def _deserialize_event(self, result):
        event_d = result["payload"]
        event_d["_zentral"] = result["metadata"]
        event_d["_zentral"]["tags"] = result["tags"]
        event_d["_zentral"]["type"] = result["type"]
        event_d["_zentral"]["created_at"] = self._datetime_to_zentral(result["created_at"])
        return event_from_event_d(event_d)

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

    # common

    @staticmethod
    def _serialize_datetime(dt):
        if not dt:
            return
        if not is_naive(dt):
            dt = make_naive(dt)
        return dt.isoformat()

    @staticmethod
    def _datetime_to_zentral(dt):
        if not dt:
            return
        if is_naive(dt):
            dt = make_aware(dt)
        return dt

    def _get_aggregated_needle_event_counts(self, needle, from_dt, to_dt=None):
        self.wait_and_configure_if_necessary()
        wheres = [
            "date >= {from_dt:Datetime(9, 'UTC')}",
            "needle = {needle:String}"
        ]
        params = {"from_dt": from_dt, "needle": needle}
        if to_dt:
            wheres.append("date < {to_dt:Datetime(9, 'UTC')}")
            params["to_dt"] = to_dt
        wheres = " AND ".join(wheres)
        query_ctx = self.client.create_query_context(
            query=f"SELECT type, sum(count) FROM `{self.table_name}_types_needles_aggs` WHERE {wheres} GROUP BY type",
            parameters=params,
        )
        aggs = {}
        for result in self.client.query(context=query_ctx).named_results():
            aggs[result["type"]] = result["sum(count)"]
        return aggs

    def _fetch_needle_events(self, needle, from_dt, to_dt=None, event_type=None, limit=10, cursor=None):
        self.wait_and_configure_if_necessary()
        wheres = [
            "has(needles, {needle:String})",
            "created_at >= toDateTime64({from_dt:String}, 9, 'UTC')",
        ]
        params = {
            "needle": needle,
            "from_dt": self._serialize_datetime(from_dt),
            "limit": limit
        }
        if cursor or to_dt:
            wheres.append("created_at < toDateTime64({to_dt:String}, 9, 'UTC')")
            if cursor:
                to_dt = cursor
            else:
                to_dt = self._serialize_datetime(to_dt)
            params["to_dt"] = to_dt
        if event_type:
            wheres.append("type = {event_type:String}")
            params["event_type"] = event_type
        wheres = " AND ".join(wheres)
        query_ctx = self.client.create_query_context(
            query=(
                f"SELECT metadata, type, tags, created_at, payload FROM `{self.table_name}` WHERE {wheres} "
                "ORDER BY created_at DESC, metadata.id.:String ASC, metadata.idx.:UInt32 ASC LIMIT {limit:UInt32}"
            ),
            parameters=params
        )
        events = []
        cursor = None
        for result in self.client.query(context=query_ctx).named_results():
            event = self._deserialize_event(result)
            if cursor is None or cursor > event.metadata.created_at:
                cursor = event.metadata.created_at
            events.append(event)
        return events, self._serialize_datetime(cursor)

    # machine events

    def fetch_machine_events(self, serial_number, from_dt, to_dt=None, event_type=None, limit=10, cursor=None):
        return self._fetch_needle_events(f"_s:{serial_number}", from_dt, to_dt, event_type, limit, cursor)

    def get_aggregated_machine_event_counts(self, serial_number, from_dt, to_dt=None):
        return self._get_aggregated_needle_event_counts(f"_s:{serial_number}", from_dt, to_dt)

    def get_last_machine_heartbeats(self, serial_number, from_dt):
        self.wait_and_configure_if_necessary()
        wheres = [
            "serial_number = {serial_number:String}",
            "last_seen >= toDateTime64({from_dt:String}, 9, 'UTC')",
        ]
        params = {
            "serial_number": serial_number,
            "from_dt": self._serialize_datetime(from_dt)
        }
        wheres = " AND ".join(wheres)
        query_ctx = self.client.create_query_context(
            query=(
                f"SELECT type, key, max(last_seen) AS max_last_seen FROM `{self.table_name}_machine_heartbeats` "
                f"WHERE {wheres} GROUP BY type, key"
            ),
            parameters=params,
        )
        heartbeat_aggs = {}
        for result in self.client.query(context=query_ctx).named_results():
            if result["type"] == "inventory_heartbeat":
                key = result["key"]
                ua = None
            else:
                key = None
                ua = result["key"]
            heartbeat_aggs.setdefault((result["type"], key), []).append((ua, result["max_last_seen"]))
        heartbeats = []
        for event_type, key in sorted(heartbeat_aggs.keys()):
            event_class = event_types.get(event_type, None)
            heartbeats.append((event_class, key, sorted(heartbeat_aggs[(event_type, key)], reverse=True)))
        return heartbeats

    # object events

    def fetch_object_events(self, key, val, from_dt, to_dt=None, event_type=None, limit=10, cursor=None):
        return self._fetch_needle_events(f"_o:{key}:{val}", from_dt, to_dt, event_type, limit, cursor)

    def get_aggregated_object_event_counts(self, key, val, from_dt, to_dt=None):
        return self._get_aggregated_needle_event_counts(f"_o:{key}:{val}", from_dt, to_dt)

    # probe events

    def fetch_probe_events(self, probe, from_dt, to_dt=None, event_type=None, limit=10, cursor=None):
        return self._fetch_needle_events(f"_p:{probe.pk}", from_dt, to_dt, event_type, limit, cursor)

    def get_aggregated_probe_event_counts(self, probe, from_dt, to_dt=None):
        return self._get_aggregated_needle_event_counts(f"_p:{probe.pk}", from_dt, to_dt)

    # zentral apps data

    def get_app_hist_data(self, interval, bucket_number, tag):
        if interval != "day":
            raise NotImplementedError("Only 'day' is supported")
        wheres = [
            "tag = {tag:String}",
            "date >= toDate(minus(NOW(), toIntervalDay({days:UInt32})))"
        ]
        params = {"tag": tag, "days": bucket_number}
        wheres = " AND ".join(wheres)
        query_ctx = self.client.create_query_context(
            query=("SELECT toDateTime(date) AS date, sum(events) AS events, uniqExactMerge(machines) AS machines "
                   f"FROM `{self.table_name}_tags_aggs` WHERE {wheres} GROUP BY date"),
            parameters=params,
        )
        data = {}
        for result in self.client.query(context=query_ctx).named_results():
            day = result["date"]
            if not is_naive(day):
                day = make_naive(day)
            data[day] = (result["events"], result["machines"])
        today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        buckets = []
        for days in range(-1 * bucket_number + 1, 1):
            day = today + timedelta(days=days)
            events, machines = data.get(day, (0, 0))
            buckets.append((day, events, machines))
        return buckets


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

from datetime import timedelta
import json
import logging
import time
from django.utils import timezone
from rest_framework import serializers
import snowflake.connector
from snowflake.connector import DictCursor
from zentral.core.events import event_from_event_d, event_types
from zentral.core.stores.backends.base import BaseStore


logger = logging.getLogger("zentral.core.stores.backends.snowflake")


class SnowflakeStore(BaseStore):
    kwargs_keys = (
        "account",
        "user",
        "password",
        "database",
        "schema",
        "role",
        "warehouse",
        "session_timeout",
    )
    encrypted_kwargs_paths = (
        ["password"],
    )

    default_schema = "PUBLIC"
    default_session_timeout = 4 * 3600 - 10 * 60  # 4 hours (Snowflake default) - 10 min

    read_only = True
    last_machine_heartbeats = True
    machine_events = True
    object_events = True
    probe_events = True

    def load(self):
        super().load()
        # connection parameters
        self._connect_kwargs = {}
        for k in ("account", "user", "password", "database", "schema", "role", "warehouse"):
            self._connect_kwargs[k] = getattr(self, k)
        # connection
        self._connection = None
        self._last_active_at = time.monotonic()

    def _get_connection(self):
        if self._connection is None or (time.monotonic() - self._last_active_at) > self.session_timeout:
            if self._connection is None:
                action = "Connect"
            else:
                logger.info("Close current connection to account %s", self.account)
                self._connection.close()
                action = "Re-connect"
            logger.info("%s to account %s", action, self.account)
            self._connection = snowflake.connector.connect(**self._connect_kwargs)
        self._last_active_at = time.monotonic()
        return self._connection

    def _deserialize_event(self, result):
        metadata = json.loads(result['METADATA'])
        metadata['type'] = result['TYPE']
        metadata['created_at'] = result['CREATED_AT']
        metadata['tags'] = json.loads(result['TAGS'])
        metadata['objects'] = {}
        for objref in json.loads(result['OBJECTS']):
            k, v = objref.split(":", 1)
            metadata['objects'].setdefault(k, []).append(v)
        metadata['serial_number'] = result['SERIAL_NUMBER']
        event_d = json.loads(result.pop("PAYLOAD"))
        event_d['_zentral'] = metadata
        return event_from_event_d(event_d)

    def _prepare_query(self, query, args=None, **kwargs):
        if args is None:
            args = []
        first_filter = True
        for attr, filter_tmpl in (("from_dt", "AND created_at >= %s"),
                                  ("to_dt", "AND created_at <= %s"),
                                  ("event_type", "AND type = %s"),
                                  ("objref", "AND ARRAY_CONTAINS(%s::variant, objects)"),
                                  ("probe", "AND ARRAY_CONTAINS(%s::variant, probes)"),
                                  ("serial_number", "AND serial_number = %s"),
                                  ("order_by", None),
                                  ("limit", "LIMIT %s"),
                                  ("offset", "OFFSET %s")):
            val = kwargs.get(attr)
            if val is not None:
                if attr == "order_by":
                    query += f" ORDER BY {val}"
                else:
                    if first_filter and filter_tmpl.startswith("AND "):
                        filter_tmpl = f"WHERE {filter_tmpl[4:]}"
                    query += f" {filter_tmpl}"
                    args.append(val)
            first_filter = False
        return query, args

    def _fetch_aggregated_event_counts(self, **kwargs):
        query, args = self._prepare_query("SELECT TYPE, COUNT(*) AS COUNT FROM ZENTRALEVENTS", **kwargs)
        query += " GROUP BY type"
        cursor = self._get_connection().cursor(DictCursor)
        cursor.execute(query, args)
        event_counts = {
            r['TYPE']: r['COUNT']
            for r in cursor.fetchall()
        }
        cursor.close()
        return event_counts

    def _fetch_events(self, **kwargs):
        kwargs["order_by"] = "CREATED_AT DESC"
        offset = int(kwargs.pop("cursor", None) or 0)
        if offset > 0:
            kwargs["offset"] = offset
        query, args = self._prepare_query("SELECT * FROM ZENTRALEVENTS", **kwargs)
        cursor = self._get_connection().cursor(DictCursor)
        cursor.execute(query, args)
        events = [self._deserialize_event(t) for t in cursor.fetchall()]
        cursor.close()
        next_cursor = None
        limit = kwargs.get("limit")
        if limit and len(events) >= limit:
            next_cursor = str(limit + kwargs.get("offset", 0))
        return events, next_cursor

    # machine events

    def fetch_machine_events(self, serial_number, from_dt, to_dt=None, event_type=None, limit=10, cursor=None):
        return self._fetch_events(
            serial_number=serial_number,
            from_dt=from_dt,
            to_dt=to_dt,
            event_type=event_type,
            limit=limit,
            cursor=cursor
        )

    def get_aggregated_machine_event_counts(self, serial_number,  from_dt, to_dt=None):
        return self._fetch_aggregated_event_counts(
            serial_number=serial_number,
            from_dt=from_dt,
            to_dt=to_dt
        )

    def get_last_machine_heartbeats(self, serial_number, from_dt):
        heartbeats = {}
        query = (
            "SELECT TYPE, MAX(CREATED_AT) LAST_SEEN,"
            "PAYLOAD:source.name::varchar SOURCE_NAME, NULL USER_AGENT "
            "FROM ZENTRALEVENTS "
            "WHERE CREATED_AT >= %s "
            "AND TYPE = 'inventory_heartbeat' "
            "AND SERIAL_NUMBER = %s "
            "GROUP BY TYPE, SOURCE_NAME, USER_AGENT "

            "UNION "

            "SELECT TYPE, MAX(CREATED_AT) LAST_SEEN,"
            "NULL SOURCE_NAME, METADATA:request.user_agent::varchar USER_AGENT "
            "FROM ZENTRALEVENTS "
            "WHERE CREATED_AT >= %s "
            "AND TYPE <> 'inventory_heartbeat' "
            "AND ARRAY_CONTAINS('heartbeat'::variant, TAGS) "
            "AND SERIAL_NUMBER = %s "
            "GROUP BY TYPE, SOURCE_NAME, USER_AGENT"
        )
        args = [from_dt, serial_number, from_dt, serial_number]
        cursor = self._get_connection().cursor(DictCursor)
        cursor.execute(query, args)
        for t in cursor.fetchall():
            event_class = event_types.get(t['TYPE'])
            if not event_class:
                logger.error("Unknown event type %s", t['TYPE'])
                continue
            key = (event_class, t['SOURCE_NAME'])
            heartbeats.setdefault(key, []).append((t['USER_AGENT'], t['LAST_SEEN']))
        cursor.close()
        return [
            (event_class, source_name, ua_max_dates)
            for (event_class, source_name), ua_max_dates in heartbeats.items()
        ]

    # object events

    def fetch_object_events(self, key, val, from_dt, to_dt=None, event_type=None, limit=10, cursor=None):
        return self._fetch_events(
            objref=f"{key}:{val}",
            from_dt=from_dt,
            to_dt=to_dt,
            event_type=event_type,
            limit=limit,
            cursor=cursor
        )

    def get_aggregated_object_event_counts(self, key, val, from_dt, to_dt=None):
        return self._fetch_aggregated_event_counts(
            objref=f"{key}:{val}",
            from_dt=from_dt,
            to_dt=to_dt
        )

    # probe events

    def fetch_probe_events(self, probe, from_dt, to_dt=None, event_type=None, limit=10, cursor=None):
        return self._fetch_events(
            probe=probe.pk,
            from_dt=from_dt,
            to_dt=to_dt,
            event_type=event_type,
            limit=limit,
            cursor=cursor
        )

    def get_aggregated_probe_event_counts(self, probe, from_dt, to_dt=None):
        return self._fetch_aggregated_event_counts(
            probe=probe.pk,
            from_dt=from_dt,
            to_dt=to_dt
        )

    # zentral apps data

    def get_app_hist_data(self, interval, bucket_number, tag):
        data = []
        query = (
            "SELECT COUNT(*) EVENT_COUNT, COUNT(DISTINCT SERIAL_NUMBER) MACHINE_COUNT,"
            "DATE_TRUNC(%s, CREATED_AT) BUCKET "
            "FROM ZENTRALEVENTS "
            "WHERE ARRAY_CONTAINS(%s::variant, TAGS) "
            "GROUP BY BUCKET ORDER BY BUCKET DESC"
        )
        if interval == "day":
            args = ["DAY", tag]
            last_value = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
            delta = timedelta(days=1)
        elif interval == "hour":
            args = ["HOUR", tag]
            last_value = timezone.now().replace(minute=0, second=0, microsecond=0)
            delta = timedelta(hours=1)
        else:
            logger.error("Unsupported interval %s", interval)
            return data
        cursor = self._get_connection().cursor(DictCursor)
        cursor.execute(query, args)
        results = {
            t['BUCKET']: (t['EVENT_COUNT'], t['MACHINE_COUNT'])
            for t in cursor.fetchall()
        }
        cursor.close()
        for bucket in (last_value - i * delta for i in range(bucket_number - 1, -1, -1)):
            try:
                event_count, machine_count = results[bucket]
            except KeyError:
                event_count = machine_count = 0
            data.append((bucket, event_count, machine_count))
        return data


# Serializers


class SnowflakeStoreSerializer(serializers.Serializer):
    account = serializers.CharField(min_length=1)
    user = serializers.CharField(min_length=1)
    password = serializers.CharField(min_length=1)
    database = serializers.CharField(min_length=1)
    schema = serializers.CharField(min_length=1, default=SnowflakeStore.default_schema)
    role = serializers.CharField(min_length=1)
    warehouse = serializers.CharField(min_length=1)
    session_timeout = serializers.IntegerField(min_value=60, default=SnowflakeStore.default_session_timeout)

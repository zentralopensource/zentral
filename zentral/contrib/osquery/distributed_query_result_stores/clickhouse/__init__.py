import json
import logging
import os
import re

import clickhouse_connect
from django.utils.functional import cached_property

from zentral.utils.time import naive_utcnow

from ..base import BaseDistributedQueryResultStore, DistributedQueryResultRow

logger = logging.getLogger("zentral.contrib.osquery.distributed_query_result_stores.clickhouse")


class DistributedQueryResultStore(BaseDistributedQueryResultStore):
    identifier_regex = re.compile(r"^[a-zA-Z_][0-9a-zA-Z_]*$")
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
        # timeouts
        "connect_timeout",
        "send_receive_timeout",
    )
    default_database = "default"
    default_table_name = "osquery_distributed_query_results"
    column_names = (
        "distributed_query_id",
        "serial_number",
        "row_index",
        "received_at",
        "row",
    )

    def __init__(self, config_d, ttl_days):
        super().__init__(config_d, ttl_days)
        self.client_kwargs = {
            k: config_d[k]
            for k in self.client_kwargs_keys
            if config_d.get(k) is not None
        }
        self.client_kwargs.setdefault("database", self.default_database)
        self.database = self.client_kwargs["database"]
        self.table_name = config_d.get("table_name", self.default_table_name)
        for identifier in (self.database, self.table_name):
            if not self.identifier_regex.match(identifier):
                raise ValueError(f"Invalid identifier: {identifier}")
        self._configured = False

    @cached_property
    def client(self):
        return clickhouse_connect.get_client(
            autogenerate_session_id=False,
            **self.client_kwargs
        )

    def migrate(self):
        migration_filepath = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "0001_initial.sql"
        )
        with open(migration_filepath) as f:
            sql = f.read()
        sql = sql.format(
            database=self.database,
            table_name=self.table_name,
            ttl_days=self.ttl_days,
        )
        for statement in (s.strip() for s in sql.split(";")):
            if not statement:
                continue
            self.client.command(statement)

    def _migrate_if_necessary(self):
        if not self._configured:
            self.migrate()
            self._configured = True

    def bulk_create(self, distributed_query_pk, serial_number, rows):
        self._migrate_if_necessary()
        received_at = naive_utcnow()
        data = [
            (distributed_query_pk,
             serial_number,
             row_index,
             received_at,
             json.dumps(row))
            for row_index, row in enumerate(rows)
        ]
        self.client.insert(
            self.table_name,
            data,
            column_names=self.column_names,
            settings={"insert_deduplication_token": f"{distributed_query_pk}:{serial_number}"},
        )

    @staticmethod
    def _search_where(q, params):
        where = "distributed_query_id = {distributed_query_pk:UInt64}"
        if q:
            where += (
                " AND (positionCaseInsensitiveUTF8(serial_number, {q:String}) > 0"
                " OR positionCaseInsensitiveUTF8(row, {q:String}) > 0)"
            )
            params["q"] = q
        return where

    def get_result_count(self, distributed_query_pk, q=None):
        self._migrate_if_necessary()
        params = {"distributed_query_pk": distributed_query_pk}
        where = self._search_where(q, params)
        result = self.client.query(
            f"SELECT uniqExact((serial_number, row_index)) FROM `{self.table_name}` WHERE {where}",
            parameters=params,
        )
        return result.result_rows[0][0]

    def get_result_counts(self, distributed_query_pks):
        self._migrate_if_necessary()
        result = self.client.query(
            f"SELECT distributed_query_id, uniqExact((serial_number, row_index)) "
            f"FROM `{self.table_name}` "
            "WHERE distributed_query_id IN {distributed_query_pks:Array(UInt64)} "
            "GROUP BY distributed_query_id",
            parameters={"distributed_query_pks": list(distributed_query_pks)},
        )
        return {dq_pk: count for dq_pk, count in result.result_rows}

    def get_results(self, distributed_query_pk, q, offset, limit):
        self._migrate_if_necessary()
        params = {"distributed_query_pk": distributed_query_pk, "offset": offset, "limit": limit}
        where = self._search_where(q, params)
        result = self.client.query(
            f"SELECT serial_number, row FROM `{self.table_name}` FINAL WHERE {where} "
            "ORDER BY serial_number, row_index LIMIT {limit:UInt64} OFFSET {offset:UInt64}",
            parameters=params,
        )
        return [
            DistributedQueryResultRow(serial_number, json.loads(row))
            for serial_number, row in result.result_rows
        ]

    def get_result_columns(self, distributed_query_pk):
        self._migrate_if_necessary()
        result = self.client.query(
            f"SELECT DISTINCT arrayJoin(JSONExtractKeys(row)) AS col FROM `{self.table_name}` "
            "WHERE distributed_query_id = {distributed_query_pk:UInt64} ORDER BY col",
            parameters={"distributed_query_pk": distributed_query_pk},
        )
        return [t[0] for t in result.result_rows]

    def iter_results(self, distributed_query_pk):
        self._migrate_if_necessary()
        with self.client.query_rows_stream(
            f"SELECT serial_number, row FROM `{self.table_name}` FINAL "
            "WHERE distributed_query_id = {distributed_query_pk:UInt64} "
            "ORDER BY serial_number, row_index",
            parameters={"distributed_query_pk": distributed_query_pk},
        ) as stream:
            for serial_number, row in stream:
                yield serial_number, json.loads(row)

    def delete_results(self, distributed_query_pk):
        self._migrate_if_necessary()
        self.client.command(
            f"DELETE FROM `{self.database}`.`{self.table_name}` "
            "WHERE distributed_query_id = {distributed_query_pk:UInt64}",
            parameters={"distributed_query_pk": distributed_query_pk},
        )

    def delete_expired_results(self, cutoff):
        self._migrate_if_necessary()
        self.client.command(
            f"DELETE FROM `{self.database}`.`{self.table_name}` "
            "WHERE received_at < toDateTime64({cutoff:String}, 6, 'UTC')",
            parameters={"cutoff": cutoff.isoformat()},
        )

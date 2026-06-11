import csv
import io
import json
from datetime import timedelta
from unittest.mock import Mock, patch

from django.core.exceptions import ImproperlyConfigured
from django.core.files.storage import default_storage
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import IntegrityError
from django.test import TestCase
from django.utils.crypto import get_random_string

from zentral.contrib.osquery.distributed_query_result_stores import _load_distributed_query_result_store
from zentral.contrib.osquery.distributed_query_result_stores.base import (
    BaseDistributedQueryResultStore,
    DistributedQueryResultRow,
)
from zentral.contrib.osquery.distributed_query_result_stores.clickhouse import (
    DistributedQueryResultStore as ClickHouseDistributedQueryResultStore,
)
from zentral.contrib.osquery.distributed_query_result_stores.postgres import (
    DistributedQueryResultStore as PostgresDistributedQueryResultStore,
)
from zentral.contrib.osquery.events import post_distributed_query_result_rows
from zentral.contrib.osquery.models import DistributedQuery, DistributedQueryResult
from zentral.contrib.osquery.preprocessors import DistributedQueryResultsPreprocessor, get_preprocessors
from zentral.contrib.osquery.tasks import _export_distributed_query_results
from zentral.utils.time import naive_utcnow


def force_distributed_query():
    return DistributedQuery.objects.create(
        sql="select username from users;",
        valid_from=naive_utcnow(),
        query_version=1
    )


def force_expired_distributed_query(days=100):
    distributed_query = DistributedQuery.objects.create(
        sql="select username from users;",
        valid_from=naive_utcnow() - timedelta(days=days),
        valid_until=naive_utcnow() - timedelta(days=days - 1),
        query_version=1
    )
    DistributedQuery.objects.filter(pk=distributed_query.pk).update(
        created_at=naive_utcnow() - timedelta(days=days)
    )
    return distributed_query


class DistributedQueryResultStoreFactoryTestCase(TestCase):
    def _load_store(self, app_config_d):
        with patch(
            "zentral.contrib.osquery.distributed_query_result_stores.settings",
            {"apps": {"zentral.contrib.osquery": app_config_d}}
        ):
            return _load_distributed_query_result_store()

    def test_default_store(self):
        store = self._load_store({})
        self.assertIsInstance(store, PostgresDistributedQueryResultStore)
        self.assertEqual(store.ttl_days, 90)

    def test_invalid_ttl(self):
        for ttl_days in (0, -1, None, "yolo"):
            with self.assertRaises(ImproperlyConfigured) as cm:
                self._load_store({"distributed_query_results_ttl_days": ttl_days})
            self.assertEqual(cm.exception.args[0], "Invalid distributed_query_results_ttl_days app setting")

    def test_clickhouse_store(self):
        store = self._load_store({
            "distributed_query_results_ttl_days": 17,
            "distributed_query_result_store": {
                "backend": "CLICKHOUSE",
                "clickhouse_kwargs": {"host": "clickhouse"}
            }
        })
        self.assertIsInstance(store, ClickHouseDistributedQueryResultStore)
        self.assertEqual(store.ttl_days, 17)
        self.assertEqual(store.config_d, {"host": "clickhouse"})

    def test_clickhouse_store_invalid_identifier(self):
        with self.assertRaises(ValueError) as cm:
            ClickHouseDistributedQueryResultStore({"host": "clickhouse", "table_name": "yolo;fomo"}, 90)
        self.assertEqual(cm.exception.args[0], "Invalid identifier: yolo;fomo")


class BaseDistributedQueryResultStoreTestCase(TestCase):
    def test_not_implemented(self):
        store = BaseDistributedQueryResultStore({}, 90)
        for method, args in (
            (store.bulk_create, (1, "0123456789", [])),
            (store.get_result_count, (1,)),
            (store.get_result_counts, ([1],)),
            (store.get_results, (1, None, 0, 10)),
            (store.get_result_columns, (1,)),
            (store.iter_results, (1,)),
            (store.delete_results, (1,)),
            (store.delete_expired_results, (naive_utcnow(),)),
        ):
            with self.assertRaises(NotImplementedError):
                method(*args)

    def test_result_row_not_a_dict(self):
        result_row = DistributedQueryResultRow("0123456789", ["not", "a", "dict"])
        self.assertEqual(list(result_row.iter_row_kv()), [])


class DistributedQueryResultPostingTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.distributed_query = force_distributed_query()

    def _post_rows(self, rows, inline=True):
        with patch("zentral.contrib.osquery.events.queues.post_raw_event") as post_raw_event:
            post_distributed_query_result_rows(self.distributed_query.pk, "0123456789", rows, inline)
        return [call_args.args for call_args in post_raw_event.call_args_list]

    def test_inline(self):
        calls = self._post_rows([{"username": "godzilla"}, {"username": "mothra"}])
        self.assertEqual(len(calls), 1)
        routing_key, raw_event = calls[0]
        self.assertEqual(routing_key, "osquery_distributed_query_results")
        self.assertEqual(
            raw_event,
            {"distributed_query_pk": self.distributed_query.pk,
             "serial_number": "0123456789",
             "rows": [{"username": "godzilla"}, {"username": "mothra"}]}
        )

    def test_null_character_removed(self):
        calls = self._post_rows([{"username": "god\u0000zilla"}])
        self.assertEqual(calls[0][1]["rows"], [{"username": "godzilla"}])

    @patch("zentral.contrib.osquery.events.default_storage")
    def test_file(self, default_storage):
        default_storage.save.return_value = "osquery/distributed_query_results/yolo.json"
        calls = self._post_rows([{"username": "godzilla"}], inline=False)
        self.assertEqual(len(calls), 1)
        routing_key, raw_event = calls[0]
        self.assertEqual(routing_key, "osquery_distributed_query_results")
        self.assertEqual(
            raw_event,
            {"distributed_query_pk": self.distributed_query.pk,
             "serial_number": "0123456789",
             "filepath": "osquery/distributed_query_results/yolo.json"}
        )
        filepath, content = default_storage.save.call_args.args
        self.assertTrue(filepath.startswith(f"osquery/distributed_query_results/{self.distributed_query.pk}/"))
        self.assertTrue(filepath.endswith(".json"))
        self.assertEqual(json.load(content), [{"username": "godzilla"}])


class DistributedQueryResultsPreprocessorTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.distributed_query = force_distributed_query()

    def _build_raw_event(self, **kwargs):
        raw_event = {
            "distributed_query_pk": self.distributed_query.pk,
            "serial_number": "0123456789",
            "rows": [{"username": "godzilla"}],
        }
        raw_event.update(**kwargs)
        return {k: v for k, v in raw_event.items() if v is not None}

    def test_store_inline_rows(self):
        preprocessor = DistributedQueryResultsPreprocessor()
        self.assertEqual(list(preprocessor.process_raw_event(self._build_raw_event())), [])
        dqr_qs = DistributedQueryResult.objects.filter(distributed_query=self.distributed_query)
        self.assertEqual(dqr_qs.count(), 1)
        self.assertEqual(dqr_qs.first().row, {"username": "godzilla"})

    def test_invalid_raw_event_dropped(self):
        preprocessor = DistributedQueryResultsPreprocessor()
        self.assertEqual(list(preprocessor.process_raw_event({"yolo": "fomo"})), [])
        self.assertEqual(DistributedQueryResult.objects.count(), 0)

    @patch("zentral.contrib.osquery.preprocessors.default_storage")
    def test_store_file(self, default_storage):
        default_storage.open.return_value.__enter__.return_value = io.BytesIO(
            json.dumps([{"username": "godzilla"}]).encode("utf-8")
        )
        raw_event = self._build_raw_event(rows=None, filepath="osquery/distributed_query_results/yolo.json")
        preprocessor = DistributedQueryResultsPreprocessor()
        self.assertEqual(list(preprocessor.process_raw_event(raw_event)), [])
        dqr_qs = DistributedQueryResult.objects.filter(distributed_query=self.distributed_query)
        self.assertEqual(dqr_qs.count(), 1)
        self.assertEqual(dqr_qs.first().row, {"username": "godzilla"})
        default_storage.open.assert_called_once_with("osquery/distributed_query_results/yolo.json")
        default_storage.delete.assert_called_once_with("osquery/distributed_query_results/yolo.json")

    @patch("zentral.contrib.osquery.preprocessors.default_storage")
    def test_missing_file_dropped(self, default_storage):
        default_storage.open.side_effect = FileNotFoundError
        raw_event = self._build_raw_event(rows=None, filepath="osquery/distributed_query_results/yolo.json")
        preprocessor = DistributedQueryResultsPreprocessor()
        self.assertEqual(list(preprocessor.process_raw_event(raw_event)), [])
        self.assertEqual(DistributedQueryResult.objects.count(), 0)
        default_storage.delete.assert_not_called()

    def test_missing_rows_and_filepath_dropped(self):
        raw_event = self._build_raw_event(rows=None)
        preprocessor = DistributedQueryResultsPreprocessor()
        self.assertEqual(list(preprocessor.process_raw_event(raw_event)), [])
        self.assertEqual(DistributedQueryResult.objects.count(), 0)

    @patch("zentral.contrib.osquery.preprocessors.default_storage")
    def test_unreadable_file_dropped(self, default_storage):
        default_storage.open.side_effect = OSError("boom")
        raw_event = self._build_raw_event(rows=None, filepath="osquery/distributed_query_results/yolo.json")
        preprocessor = DistributedQueryResultsPreprocessor()
        self.assertEqual(list(preprocessor.process_raw_event(raw_event)), [])
        self.assertEqual(DistributedQueryResult.objects.count(), 0)
        default_storage.delete.assert_not_called()

    @patch("zentral.contrib.osquery.preprocessors.default_storage")
    def test_file_delete_error(self, default_storage):
        default_storage.open.return_value.__enter__.return_value = io.BytesIO(
            json.dumps([{"username": "godzilla"}]).encode("utf-8")
        )
        default_storage.delete.side_effect = OSError("boom")
        raw_event = self._build_raw_event(rows=None, filepath="osquery/distributed_query_results/yolo.json")
        preprocessor = DistributedQueryResultsPreprocessor()
        self.assertEqual(list(preprocessor.process_raw_event(raw_event)), [])
        self.assertEqual(DistributedQueryResult.objects.count(), 1)

    def test_get_preprocessors(self):
        preprocessors = list(get_preprocessors())
        self.assertEqual(len(preprocessors), 1)
        self.assertEqual(preprocessors[0].routing_key, "osquery_distributed_query_results")

    @patch("zentral.contrib.osquery.preprocessors.get_distributed_query_result_store")
    def test_store_error_dropped(self, get_store):
        get_store.return_value = Mock(bulk_create=Mock(side_effect=ValueError("boom")))
        preprocessor = DistributedQueryResultsPreprocessor()
        self.assertEqual(list(preprocessor.process_raw_event(self._build_raw_event())), [])
        self.assertEqual(DistributedQueryResult.objects.count(), 0)


class PostgresDistributedQueryResultStoreTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.store = PostgresDistributedQueryResultStore({}, 90)
        cls.distributed_query = force_distributed_query()
        cls.store.bulk_create(
            cls.distributed_query.pk, "0123456789",
            [{"username": "godzilla"}, {"username": "mothra"}]
        )

    def test_get_result_count(self):
        self.assertEqual(self.store.get_result_count(self.distributed_query.pk), 2)
        self.assertEqual(self.store.get_result_count(self.distributed_query.pk, "godz"), 1)
        self.assertEqual(self.store.get_result_count(self.distributed_query.pk, "ghidorah"), 0)

    def test_get_result_counts(self):
        self.assertEqual(
            self.store.get_result_counts([self.distributed_query.pk, 0]),
            {self.distributed_query.pk: 2}
        )

    def test_get_results(self):
        results = self.store.get_results(self.distributed_query.pk, None, 0, 10)
        self.assertEqual(len(results), 2)
        results = self.store.get_results(self.distributed_query.pk, "mothra", 0, 10)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].serial_number, "0123456789")
        self.assertEqual(results[0].row, {"username": "mothra"})
        self.assertEqual(list(results[0].iter_row_kv()), [("username", "mothra")])

    def test_get_result_columns(self):
        self.assertEqual(self.store.get_result_columns(self.distributed_query.pk), ["username"])

    def test_iter_results(self):
        self.assertEqual(
            sorted(row["username"] for _, row in self.store.iter_results(self.distributed_query.pk)),
            ["godzilla", "mothra"]
        )

    def test_bulk_create_deleted_distributed_query(self):
        distributed_query = force_distributed_query()
        distributed_query_pk = distributed_query.pk
        distributed_query.delete()
        self.store.bulk_create(distributed_query_pk, "0123456789", [{"username": "godzilla"}])
        self.assertEqual(self.store.get_result_count(distributed_query_pk), 0)

    @patch("zentral.contrib.osquery.models.DistributedQueryResult.objects.bulk_create")
    def test_bulk_create_integrity_error_reraised(self, orm_bulk_create):
        orm_bulk_create.side_effect = IntegrityError("boom")
        with self.assertRaises(IntegrityError):
            self.store.bulk_create(self.distributed_query.pk, "0123456789", [{"username": "godzilla"}])

    @patch("zentral.contrib.osquery.models.DistributedQuery.objects.filter")
    @patch("zentral.contrib.osquery.models.DistributedQueryResult.objects.bulk_create")
    def test_bulk_create_distributed_query_deleted_during_insert(self, orm_bulk_create, dq_filter):
        orm_bulk_create.side_effect = IntegrityError("boom")
        dq_filter.return_value = Mock(exists=Mock(side_effect=[True, False]))
        self.store.bulk_create(self.distributed_query.pk, "0123456789", [{"username": "godzilla"}])

    def test_delete_expired_results(self):
        expired_distributed_query = force_expired_distributed_query()
        self.store.bulk_create(expired_distributed_query.pk, "0123456789", [{"username": "ghidorah"}])
        open_ended_distributed_query = force_distributed_query()
        DistributedQuery.objects.filter(pk=open_ended_distributed_query.pk).update(
            created_at=naive_utcnow() - timedelta(days=100)
        )
        self.store.bulk_create(open_ended_distributed_query.pk, "0123456789", [{"username": "rodan"}])
        deleted = self.store.delete_expired_results(naive_utcnow() - timedelta(days=90))
        self.assertEqual(deleted, 1)
        self.assertEqual(self.store.get_result_count(expired_distributed_query.pk), 0)
        # the run without an end of validity may still collect results, they are kept
        self.assertEqual(self.store.get_result_count(open_ended_distributed_query.pk), 1)
        # the recent results are kept
        self.assertEqual(self.store.get_result_count(self.distributed_query.pk), 2)


class ClickHouseDistributedQueryResultStoreTestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.database = "zentral_tests"
        cls.store = ClickHouseDistributedQueryResultStore({
            "host": "clickhouse",
            "port": 8123,
            "secure": False,
            "database": cls.database,
            "username": cls.database,
            "password": cls.database,
            "table_name": f"test_dqr_{get_random_string(8).lower()}",
        }, ttl_days=15)

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        cls.store.client.command(f"DROP TABLE IF EXISTS `{cls.database}`.`{cls.store.table_name}`;")

    def setUp(self):
        self.distributed_query_pk = force_distributed_query().pk
        self.store.bulk_create(
            self.distributed_query_pk, "0123456789",
            [{"username": "godzilla"}, {"username": "mothra"}]
        )

    def test_get_result_count(self):
        self.assertEqual(self.store.get_result_count(self.distributed_query_pk), 2)
        self.assertEqual(self.store.get_result_count(self.distributed_query_pk, "GODZ"), 1)
        self.assertEqual(self.store.get_result_count(self.distributed_query_pk, "ghidorah"), 0)

    def test_duplicated_results_deduplicated(self):
        self.store.bulk_create(
            self.distributed_query_pk, "0123456789",
            [{"username": "godzilla"}, {"username": "mothra"}]
        )
        self.assertEqual(self.store.get_result_count(self.distributed_query_pk), 2)
        self.assertEqual(len(self.store.get_results(self.distributed_query_pk, None, 0, 10)), 2)

    def test_get_result_counts(self):
        self.assertEqual(
            self.store.get_result_counts([self.distributed_query_pk, 0]),
            {self.distributed_query_pk: 2}
        )

    def test_get_results(self):
        results = self.store.get_results(self.distributed_query_pk, None, 0, 10)
        self.assertEqual(len(results), 2)
        results = self.store.get_results(self.distributed_query_pk, "mothra", 0, 10)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].serial_number, "0123456789")
        self.assertEqual(results[0].row, {"username": "mothra"})
        self.assertEqual(list(results[0].iter_row_kv()), [("username", "mothra")])

    def test_get_result_columns(self):
        self.assertEqual(self.store.get_result_columns(self.distributed_query_pk), ["username"])

    def test_iter_results(self):
        self.assertEqual(
            sorted(row["username"] for _, row in self.store.iter_results(self.distributed_query_pk)),
            ["godzilla", "mothra"]
        )

    def test_delete_results(self):
        self.store.delete_results(self.distributed_query_pk)
        self.assertEqual(self.store.get_result_count(self.distributed_query_pk), 0)

    def test_delete_expired_results(self):
        self.assertIsNone(self.store.delete_expired_results(naive_utcnow() - timedelta(days=1)))
        self.assertEqual(self.store.get_result_count(self.distributed_query_pk), 2)
        self.assertIsNone(self.store.delete_expired_results(naive_utcnow() + timedelta(days=1)))
        self.assertEqual(self.store.get_result_count(self.distributed_query_pk), 0)


class CleanupDistributedQueryResultsCommandTestCase(TestCase):
    def test_cleanup(self):
        expired_distributed_query = force_expired_distributed_query()
        store = PostgresDistributedQueryResultStore({}, 90)
        store.bulk_create(expired_distributed_query.pk, "0123456789", [{"username": "ghidorah"}])
        out = io.StringIO()
        call_command("cleanup_osquery_distributed_query_results", "--days", "90", stdout=out)
        self.assertIn("1 result deleted", out.getvalue())
        self.assertEqual(store.get_result_count(expired_distributed_query.pk), 0)

    def test_cleanup_quiet(self):
        out = io.StringIO()
        call_command("cleanup_osquery_distributed_query_results", "-q", "--days", "90", stdout=out)
        self.assertEqual(out.getvalue(), "")

    def test_cleanup_invalid_days(self):
        with self.assertRaises(CommandError) as cm:
            call_command("cleanup_osquery_distributed_query_results", days=-1)
        self.assertEqual(cm.exception.args[0], "No number of days to keep")

    @patch("zentral.contrib.osquery.management.commands"
           ".cleanup_osquery_distributed_query_results.get_distributed_query_result_store")
    def test_cleanup_async_store(self, get_store):
        get_store.return_value = Mock(ttl_days=90, delete_expired_results=Mock(return_value=None))
        out = io.StringIO()
        call_command("cleanup_osquery_distributed_query_results", stdout=out)
        self.assertIn("results deletion submitted", out.getvalue())


class ExportDistributedQueryResultsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.distributed_query = force_distributed_query()
        store = PostgresDistributedQueryResultStore({}, 90)
        store.bulk_create(
            cls.distributed_query.pk, "0123456789",
            [{"username": "godzilla", "uid": 501, "admin": True, "shell": None}]
        )

    def _export(self, extension):
        result = _export_distributed_query_results(self.distributed_query, extension)
        filepath = result["filepath"]
        self.assertTrue(default_storage.exists(filepath))
        with default_storage.open(filepath) as f:
            content = f.read()
        default_storage.delete(filepath)
        return result, content

    def test_export_csv(self):
        result, content = self._export(".csv")
        self.assertEqual(result["headers"]["Content-Type"], "text/csv")
        rows = list(csv.reader(io.StringIO(content.decode("utf-8"))))
        self.assertEqual(rows[0], ["serial number", "admin", "shell", "uid", "username"])
        self.assertEqual(rows[1], ["0123456789", "True", "", "501", "godzilla"])

    def test_export_ndjson(self):
        result, content = self._export(".ndjson")
        self.assertEqual(result["headers"]["Content-Type"], "application/x-ndjson")
        self.assertEqual(
            json.loads(content.decode("utf-8").strip()),
            {"serial_number": "0123456789",
             "row": {"username": "godzilla", "uid": 501, "admin": True, "shell": None}}
        )

    def test_export_xlsx(self):
        result, content = self._export(".xlsx")
        self.assertEqual(result["headers"]["Content-Type"],
                         "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        self.assertTrue(content.startswith(b"PK"))

    def test_export_unsupported_extension(self):
        with self.assertRaises(ValueError):
            _export_distributed_query_results(self.distributed_query, ".yolo")

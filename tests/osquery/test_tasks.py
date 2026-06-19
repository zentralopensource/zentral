from django.core.files.storage import default_storage
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.osquery.models import DistributedQuery, DistributedQueryResult, Query
from zentral.contrib.osquery.tasks import export_distributed_query_results
from zentral.utils.time import naive_utcnow


class OsqueryTasksTest(TestCase):
    def _force_distributed_query_with_result(self):
        query = Query.objects.create(name=get_random_string(12), sql="select * from osquery_schedule;")
        distributed_query = DistributedQuery.objects.create(
            query=query,
            query_version=query.version,
            sql=query.sql,
            valid_from=naive_utcnow(),
        )
        DistributedQueryResult.objects.create(
            distributed_query=distributed_query,
            serial_number=get_random_string(12),
            # a string, a number, an empty value and a non-scalar value to
            # exercise the xlsx cell-type branches
            row={"name": "osqueryd", "interval": 60, "path": "", "args": ["--flag"]},
        )
        return distributed_query

    def test_export_distributed_query_results_xlsx(self):
        distributed_query = self._force_distributed_query_with_result()
        result = export_distributed_query_results(distributed_query.pk, ".xlsx")
        self.assertTrue(result["filepath"].endswith(".xlsx"))
        self.assertTrue(default_storage.exists(result["filepath"]))
        self.assertEqual(
            result["headers"]["Content-Type"],
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )

    def test_export_distributed_query_results_csv(self):
        distributed_query = self._force_distributed_query_with_result()
        result = export_distributed_query_results(distributed_query.pk, ".csv")
        self.assertTrue(result["filepath"].endswith(".csv"))
        self.assertTrue(default_storage.exists(result["filepath"]))
        self.assertEqual(result["headers"]["Content-Type"], "text/csv")

    def test_export_distributed_query_results_ndjson(self):
        distributed_query = self._force_distributed_query_with_result()
        result = export_distributed_query_results(distributed_query.pk, ".ndjson")
        self.assertTrue(result["filepath"].endswith(".ndjson"))
        self.assertTrue(default_storage.exists(result["filepath"]))
        self.assertEqual(result["headers"]["Content-Type"], "application/x-ndjson")

    def test_export_distributed_query_results_unsupported_extension(self):
        distributed_query = self._force_distributed_query_with_result()
        with self.assertRaises(ValueError):
            export_distributed_query_results(distributed_query.pk, ".yolo")

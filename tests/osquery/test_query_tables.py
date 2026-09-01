from django.test import TestCase
from django.utils.crypto import get_random_string

from zentral.contrib.osquery.models import DistributedQuery, Query
from zentral.utils.time import naive_utcnow


class QueryTablesTestCase(TestCase):
    def _force_query(self, sql="select 1 from processes;"):
        return Query.objects.create(name=get_random_string(12), sql=sql)

    # Query.tables

    def test_tables(self):
        query = self._force_query("select * from users u join groups g on (u.gid = g.gid);")
        self.assertEqual(query.tables, ["groups", "users"])

    def test_tables_empty_for_a_query_without_table(self):
        self.assertEqual(self._force_query("select 'OK' as ztl_status;").tables, [])

    # the form and the serializers reject the SQL they cannot parse. this is the fallback for the
    # paths that do not validate, the shell and the tests.
    def test_tables_empty_for_unparsable_sql(self):
        with self.assertLogs("zentral.utils.sql", level="DEBUG"):
            self.assertEqual(self._force_query("changed sql line;").tables, [])

    # DistributedQuery

    def test_snapshot_query(self):
        query = self._force_query()
        query.minimum_osquery_version = "5.10.2"
        query.platforms = ["darwin"]
        query.save()
        distributed_query = DistributedQuery(valid_from=naive_utcnow())
        distributed_query.snapshot_query(query)
        distributed_query.save()
        distributed_query.refresh_from_db()
        self.assertEqual(distributed_query.query, query)
        self.assertEqual(distributed_query.query_version, query.version)
        self.assertEqual(distributed_query.sql, query.sql)
        self.assertEqual(distributed_query.platforms, ["darwin"])
        self.assertEqual(distributed_query.minimum_osquery_version, "5.10.2")

import os
import unittest
from zentral.core.stores.backends.postgres import EventStore as PostgresEventStore
from . import BaseTestEventStore


class TestPostgresEventStore(unittest.TestCase, BaseTestEventStore):

    def setUp(self):
        # use the django default test db
        store_settings = {'database': 'test_{}'.format(os.environ.get('POSTGRES_DB', 'zentral')),
                          'user': os.environ.get('POSTGRES_USER', 'zentral'),
                          'store_name': 'postgres_test'}
        host = os.environ.get('POSTGRES_HOST')
        if host:
            store_settings['host'] = host
        password = os.environ.get('POSTGRES_PASSWORD')
        if password:
            store_settings['password'] = password
        self.event_store = PostgresEventStore(store_settings)

    def tearDown(self):
        with self.event_store._conn:
            with self.event_store._conn.cursor() as cur:
                cur.execute("delete from events *;")
        self.event_store.close()


if __name__ == '__main__':
    unittest.main()

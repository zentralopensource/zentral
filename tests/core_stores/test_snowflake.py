from datetime import datetime
import uuid
from unittest.mock import patch, Mock
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.events import InventoryHeartbeat
from zentral.contrib.osquery.events import OsqueryRequestEvent
from accounts.events import LoginEvent
from accounts.models import Group
from zentral.core.stores.backends.all import StoreBackend
from zentral.core.stores.backends.snowflake import SnowflakeStore, SnowflakeStoreSerializer
from .utils import force_store


class SnowflakeStoreTestCase(TestCase):
    maxDiff = None

    def get_store(self, **kwargs):
        for arg, default in (("account", "account"),
                             ("user", "yolo"),
                             ("password", "fomo"),
                             ("database", "database"),
                             ("schema", "PUBLIC"),
                             ("role", "role"),
                             ("warehouse", "warehouse"),
                             ("session_timeout", 123)):
            if arg not in kwargs:
                kwargs[arg] = default
        return force_store(backend=StoreBackend.Snowflake, backend_kwargs=kwargs)

    # backend model

    def test_backend_get_backend(self):
        store = self.get_store()
        self.assertIsInstance(store, SnowflakeStore)
        self.assertEqual(
            store._connect_kwargs,
            {"account": "account",
             "user": "yolo",
             "password": "fomo",
             "database": "database",
             "schema": "PUBLIC",
             "role": "role",
             "warehouse": "warehouse"}
        )
        self.assertEqual(store.session_timeout, 123)
        store2 = store.instance.get_backend(load=True)
        self.assertIsInstance(store2, SnowflakeStore)
        self.assertEqual(store2.instance, store.instance)

    def test_backend_encrypted_kwargs(self):
        store = self.get_store()
        self.assertEqual(
            store.instance.backend_kwargs,
            {'account': 'account',
             'user': 'yolo',
             'password': 'noop$Zm9tbw==',  # "encrypted"
             'database': 'database',
             'schema': 'PUBLIC',
             'role': 'role',
             'warehouse': 'warehouse',
             'session_timeout': 123},
        )

    def test_backend_serialize_for_event(self):
        store = self.get_store()
        store.instance.provisioning_uid = get_random_string(12)
        store.instance.save()
        role = Group.objects.create(name=get_random_string(12))
        store.instance.events_url_authorized_roles.add(role)
        self.assertEqual(
            store.instance.serialize_for_event(),
            {'admin_console': False,
             'backend': 'SNOWFLAKE',
             'backend_kwargs': {
                 'account': 'account',
                 'user': 'yolo',
                 'password_hash': '48ffcddb8b19a5f98d4b1b8c08b4024b12b6f24affeb50b1265aed528a2dd671',
                 'database': 'database',
                 'schema': 'PUBLIC',
                 'role': 'role',
                 'warehouse': 'warehouse',
                 'session_timeout': 123
             },
             'created_at': store.instance.created_at,
             'description': '',
             'event_filters': {},
             'events_url_authorized_roles': [{'name': role.name, 'pk': role.pk}],
             'name': store.instance.name,
             'pk': str(store.instance.pk),
             'provisioning_uid': store.instance.provisioning_uid,
             'updated_at': store.instance.updated_at}
        )
        self.assertEqual(store.session_timeout, 123)

    # event serialization

    def test_deserialize_event(self):
        serialized_event = {
            'CREATED_AT': '2022-08-20T09:50:03.848542',
            'METADATA': '{"id": "d304f4f6-7a2f-4d1e-91f6-da673104748b", "index": 3, '
                        '"namespace": "zentral", "request": {"user_agent": "user_agent", '
                        '"ip": "203.0.113.10"}, "probes": [{"pk": 18, "name": '
                        '"DfARpBxpYIBq"}]}',
            'OBJECTS': '["osquery_enrollment:19"]',
            'PAYLOAD': '{"user": {"username": "QeI99eAhCmWH"}}',
            'PROBES': '[18]',
            'SERIAL_NUMBER': None,
            'TAGS': '["yolo", "fomo", "zentral"]',
            'TYPE': 'zentral_login'
        }
        event = self.get_store()._deserialize_event(serialized_event)
        self.assertIsInstance(event, LoginEvent)
        metadata = event.metadata
        self.assertEqual(set(metadata.tags), {"yolo", "fomo", "zentral"})
        self.assertEqual(
            metadata.objects,
            {"osquery_enrollment": [["19"]]}
        )
        self.assertEqual(
            metadata.probes,
            [{"pk": 18, "name": "DfARpBxpYIBq"}]
        )
        self.assertEqual(
            event.payload,
            {"user": {"username": "QeI99eAhCmWH"}}
        )

    def test_prepare_query(self):
        query, args = self.get_store()._prepare_query(
            "SELECT * FROM ZENTRALEVENTS",
            from_dt=datetime(2022, 1, 1),
            to_dt=datetime(2023, 1, 1),
            event_type="zentral_login",
            objref="osquery_enrollment:19",
            probe=18,
            serial_number="0123456789",
            order_by="CREATED_AT DESC",
            limit=10,
            offset=20
        )
        self.assertEqual(
            query,
            "SELECT * FROM ZENTRALEVENTS "
            "WHERE created_at >= %s "
            "AND created_at <= %s "
            "AND type = %s "
            "AND ARRAY_CONTAINS(%s::variant, objects) "
            "AND ARRAY_CONTAINS(%s::variant, probes) "
            "AND serial_number = %s "
            "ORDER BY CREATED_AT DESC "
            "LIMIT %s "
            "OFFSET %s"
        )
        self.assertEqual(
            args,
            [datetime(2022, 1, 1),
             datetime(2023, 1, 1),
             "zentral_login",
             "osquery_enrollment:19",
             18,
             "0123456789",
             10,
             20]
        )

    # event storage

    @patch("zentral.core.stores.backends.snowflake.snowflake.connector.connect")
    def test_new_connection(self, connect):
        store = self.get_store()
        store._get_connection()
        connect.assert_called_once_with(**store._connect_kwargs)

    @patch("zentral.core.stores.backends.snowflake.snowflake.connector.connect")
    def test_reuse_connection(self, connect):
        store = self.get_store()
        store._get_connection()
        store._get_connection()
        connect.assert_called_once_with(**store._connect_kwargs)

    @patch("zentral.core.stores.backends.snowflake.snowflake.connector.connect")
    def test_reconnect_connection(self, connect):
        connection = Mock()
        connect.return_value = connection
        store = self.get_store()
        store._get_connection()
        # fake expired session
        store._last_active_at -= store.session_timeout
        store._get_connection()
        connection.close.assert_called_once_with()
        self.assertEqual(connect.call_count, 2)

    @patch("zentral.core.stores.backends.snowflake.snowflake.connector.connect")
    def test_fetch_machine_events(self, connect):
        cursor = Mock()
        cursor.fetchall.return_value = [
            {'CREATED_AT': '2022-08-20T09:50:03.848542',
             'METADATA': '{"id": "d304f4f6-7a2f-4d1e-91f6-da673104748b", "index": 3, '
                         '"namespace": "zentral", "request": {"user_agent": "user_agent", '
                         '"ip": "203.0.113.10"}, "probes": [{"pk": 18, "name": '
                         '"DfARpBxpYIBq"}]}',
             'OBJECTS': '["osquery_enrollment:19"]',
             'PAYLOAD': '{"user": {"username": "QeI99eAhCmWH"}}',
             'PROBES': '[18]',
             'SERIAL_NUMBER': "0123456789",
             'TAGS': '["yolo", "fomo", "zentral"]',
             'TYPE': 'zentral_login'}
        ]
        connection = Mock()
        connection.cursor.return_value = cursor
        connect.return_value = connection
        store = self.get_store()
        events, next_cursor = store.fetch_machine_events("0123456789", datetime(2022, 1, 1), limit=1, cursor="2")
        cursor.execute.assert_called_once_with(
            "SELECT * FROM ZENTRALEVENTS WHERE created_at >= %s "
            "AND serial_number = %s "
            "ORDER BY CREATED_AT DESC LIMIT %s OFFSET %s",
            [datetime(2022, 1, 1), "0123456789", 1, 2]
        )
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, LoginEvent)
        self.assertEqual(event.metadata.uuid, uuid.UUID("d304f4f6-7a2f-4d1e-91f6-da673104748b"))
        self.assertEqual(event.metadata.index, 3)
        self.assertEqual(next_cursor, "3")

    @patch("zentral.core.stores.backends.snowflake.snowflake.connector.connect")
    def test_fetch_machine_events_no_next_cursor(self, connect):
        cursor = Mock()
        cursor.fetchall.return_value = [
            {'CREATED_AT': '2022-08-20T09:50:03.848542',
             'METADATA': '{"id": "d304f4f6-7a2f-4d1e-91f6-da673104748b", "index": 3, '
                         '"namespace": "zentral", "request": {"user_agent": "user_agent", '
                         '"ip": "203.0.113.10"}, "probes": [{"pk": 18, "name": '
                         '"DfARpBxpYIBq"}]}',
             'OBJECTS': '["osquery_enrollment:19"]',
             'PAYLOAD': '{"user": {"username": "QeI99eAhCmWH"}}',
             'PROBES': '[18]',
             'SERIAL_NUMBER': "0123456789",
             'TAGS': '["yolo", "fomo", "zentral"]',
             'TYPE': 'zentral_login'}
        ]
        connection = Mock()
        connection.cursor.return_value = cursor
        connect.return_value = connection
        store = self.get_store()
        events, next_cursor = store.fetch_machine_events("0123456789", datetime(2022, 1, 1), limit=10, cursor="20")
        connect.assert_called_once_with(**store._connect_kwargs)
        cursor.execute.assert_called_once_with(
            "SELECT * FROM ZENTRALEVENTS WHERE created_at >= %s "
            "AND serial_number = %s "
            "ORDER BY CREATED_AT DESC LIMIT %s OFFSET %s",
            [datetime(2022, 1, 1), "0123456789", 10, 20]
        )
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, LoginEvent)
        self.assertEqual(event.metadata.uuid, uuid.UUID("d304f4f6-7a2f-4d1e-91f6-da673104748b"))
        self.assertEqual(event.metadata.index, 3)
        self.assertIsNone(next_cursor)

    @patch("zentral.core.stores.backends.snowflake.snowflake.connector.connect")
    def test_get_aggregated_machine_event_counts(self, connect):
        cursor = Mock()
        cursor.fetchall.return_value = [
            {"TYPE": "osquery_request", "COUNT": 17},
            {"TYPE": "munki_enrollment", "COUNT": 16}
        ]
        connection = Mock()
        connection.cursor.return_value = cursor
        connect.return_value = connection
        store = self.get_store()
        self.assertEqual(
            store.get_aggregated_machine_event_counts("0123456789", datetime(2022, 1, 1)),
            {"osquery_request": 17, "munki_enrollment": 16}
        )
        cursor.execute.assert_called_once_with(
            "SELECT TYPE, COUNT(*) AS COUNT FROM ZENTRALEVENTS "
            "WHERE created_at >= %s AND serial_number = %s "
            "GROUP BY type",
            [datetime(2022, 1, 1), "0123456789"]
        )

    @patch("zentral.core.stores.backends.snowflake.snowflake.connector.connect")
    def test_get_last_machine_heartbeats(self, connect):
        cursor = Mock()
        cursor.fetchall.return_value = [
            {"TYPE": "osquery_request", "LAST_SEEN": datetime(2022, 8, 1),
             "SOURCE_NAME": None, "USER_AGENT": "osquery/5.4.0"},
            {"TYPE": "osquery_request", "LAST_SEEN": datetime(2022, 7, 1),
             "SOURCE_NAME": None, "USER_AGENT": "osquery/5.3.0"},
            {"TYPE": "inventory_heartbeat", "LAST_SEEN": datetime(2022, 8, 2),
             "SOURCE_NAME": "Santa", "USER_AGENT": None}
        ]
        connection = Mock()
        connection.cursor.return_value = cursor
        connect.return_value = connection
        store = self.get_store()
        self.assertEqual(
            store.get_last_machine_heartbeats("0123456789", datetime(2022, 1, 1)),
            [(OsqueryRequestEvent, None, [("osquery/5.4.0", datetime(2022, 8, 1)),
                                          ("osquery/5.3.0", datetime(2022, 7, 1))]),
             (InventoryHeartbeat, "Santa", [(None, datetime(2022, 8, 2))])]
        )

    @patch("zentral.core.stores.backends.snowflake.snowflake.connector.connect")
    def test_object_events(self, connect):
        cursor = Mock()
        cursor.fetchall.return_value = [
            {'CREATED_AT': '2022-08-20T09:50:03.848542',
             'METADATA': '{"id": "d304f4f6-7a2f-4d1e-91f6-da673104748b", "index": 3, '
                         '"namespace": "zentral", "request": {"user_agent": "user_agent", '
                         '"ip": "203.0.113.10"}, "probes": [{"pk": 18, "name": '
                         '"DfARpBxpYIBq"}]}',
             'OBJECTS': '["osquery_enrollment:19"]',
             'PAYLOAD': '{"user": {"username": "QeI99eAhCmWH"}}',
             'PROBES': '[18]',
             'SERIAL_NUMBER': "0123456789",
             'TAGS': '["yolo", "fomo", "zentral"]',
             'TYPE': 'zentral_login'}
        ]
        connection = Mock()
        connection.cursor.return_value = cursor
        connect.return_value = connection
        store = self.get_store()
        events, next_cursor = store.fetch_object_events(
                "osquery_enrollment", "19",
                datetime(2022, 1, 1), limit=1, cursor="2"
        )
        connect.assert_called_once_with(**store._connect_kwargs)
        cursor.execute.assert_called_once_with(
            "SELECT * FROM ZENTRALEVENTS WHERE created_at >= %s "
            "AND ARRAY_CONTAINS(%s::variant, objects) "
            "ORDER BY CREATED_AT DESC LIMIT %s OFFSET %s",
            [datetime(2022, 1, 1), "osquery_enrollment:19", 1, 2]
        )
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, LoginEvent)
        self.assertEqual(event.metadata.uuid, uuid.UUID("d304f4f6-7a2f-4d1e-91f6-da673104748b"))
        self.assertEqual(event.metadata.index, 3)
        self.assertEqual(next_cursor, "3")

    @patch("zentral.core.stores.backends.snowflake.snowflake.connector.connect")
    def test_get_aggregated_object_event_counts(self, connect):
        cursor = Mock()
        cursor.fetchall.return_value = [
            {"TYPE": "osquery_enrollment", "COUNT": 17},
        ]
        connection = Mock()
        connection.cursor.return_value = cursor
        connect.return_value = connection
        store = self.get_store()
        self.assertEqual(
            store.get_aggregated_object_event_counts("osquery_enrollment", "19", datetime(2022, 1, 1)),
            {"osquery_enrollment": 17}
        )
        cursor.execute.assert_called_once_with(
            "SELECT TYPE, COUNT(*) AS COUNT FROM ZENTRALEVENTS "
            "WHERE created_at >= %s AND ARRAY_CONTAINS(%s::variant, objects) "
            "GROUP BY type",
            [datetime(2022, 1, 1), "osquery_enrollment:19"]
        )

    @patch("zentral.core.stores.backends.snowflake.snowflake.connector.connect")
    def test_probe_events(self, connect):
        cursor = Mock()
        cursor.fetchall.return_value = [
            {'CREATED_AT': '2022-08-20T09:50:03.848542',
             'METADATA': '{"id": "d304f4f6-7a2f-4d1e-91f6-da673104748b", "index": 3, '
                         '"namespace": "zentral", "request": {"user_agent": "user_agent", '
                         '"ip": "203.0.113.10"}, "probes": [{"pk": 18, "name": '
                         '"DfARpBxpYIBq"}]}',
             'OBJECTS': '["osquery_enrollment:19"]',
             'PAYLOAD': '{"user": {"username": "QeI99eAhCmWH"}}',
             'PROBES': '[18]',
             'SERIAL_NUMBER': "0123456789",
             'TAGS': '["yolo", "fomo", "zentral"]',
             'TYPE': 'zentral_login'}
        ]
        connection = Mock()
        connection.cursor.return_value = cursor
        connect.return_value = connection
        store = self.get_store()
        probe = Mock(pk=18)
        events, next_cursor = store.fetch_probe_events(probe, datetime(2022, 1, 1), limit=1, cursor="2")
        connect.assert_called_once_with(**store._connect_kwargs)
        cursor.execute.assert_called_once_with(
            "SELECT * FROM ZENTRALEVENTS WHERE created_at >= %s "
            "AND ARRAY_CONTAINS(%s::variant, probes) "
            "ORDER BY CREATED_AT DESC LIMIT %s OFFSET %s",
            [datetime(2022, 1, 1), 18, 1, 2]
        )
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, LoginEvent)
        self.assertEqual(event.metadata.uuid, uuid.UUID("d304f4f6-7a2f-4d1e-91f6-da673104748b"))
        self.assertEqual(event.metadata.index, 3)
        self.assertEqual(next_cursor, "3")

    @patch("zentral.core.stores.backends.snowflake.snowflake.connector.connect")
    def test_get_aggregated_probe_event_counts(self, connect):
        cursor = Mock()
        cursor.fetchall.return_value = [
            {"TYPE": "osquery_enrollment", "COUNT": 17},
        ]
        connection = Mock()
        connection.cursor.return_value = cursor
        connect.return_value = connection
        store = self.get_store()
        probe = Mock(pk=18)
        self.assertEqual(
            store.get_aggregated_probe_event_counts(probe, datetime(2022, 1, 1)),
            {"osquery_enrollment": 17}
        )
        cursor.execute.assert_called_once_with(
            "SELECT TYPE, COUNT(*) AS COUNT FROM ZENTRALEVENTS "
            "WHERE created_at >= %s AND ARRAY_CONTAINS(%s::variant, probes) "
            "GROUP BY type",
            [datetime(2022, 1, 1), 18]
        )

    def test_get_app_hist_data_unsupported_interval(self):
        self.assertEqual(self.get_store().get_app_hist_data("yolo", 12, "fomo"), [])

    @patch("zentral.core.stores.backends.snowflake.timezone.now")
    @patch("zentral.core.stores.backends.snowflake.snowflake.connector.connect")
    def test_get_hourly_app_hist_data(self, connect, tznow):
        tznow.return_value = datetime(2022, 9, 20, 11, 17)
        cursor = Mock()
        cursor.fetchall.return_value = [
            {'EVENT_COUNT': 323, 'MACHINE_COUNT': 5, 'BUCKET': datetime(2022, 9, 20, 10)}
        ]
        connection = Mock()
        connection.cursor.return_value = cursor
        connect.return_value = connection
        store = self.get_store()
        self.assertEqual(
            store.get_app_hist_data("hour", 3, "osquery"),
            [(datetime(2022, 9, 20, 9), 0, 0),
             (datetime(2022, 9, 20, 10), 323, 5),
             (datetime(2022, 9, 20, 11), 0, 0)]
        )

    @patch("zentral.core.stores.backends.snowflake.timezone.now")
    @patch("zentral.core.stores.backends.snowflake.snowflake.connector.connect")
    def test_get_daily_app_hist_data(self, connect, tznow):
        tznow.return_value = datetime(2022, 9, 20, 11, 17)
        cursor = Mock()
        cursor.fetchall.return_value = [
            {'EVENT_COUNT': 322, 'MACHINE_COUNT': 4, 'BUCKET': datetime(2022, 9, 19)}
        ]
        connection = Mock()
        connection.cursor.return_value = cursor
        connect.return_value = connection
        store = self.get_store()
        self.assertEqual(
            store.get_app_hist_data("day", 4, "osquery"),
            [(datetime(2022, 9, 17), 0, 0),
             (datetime(2022, 9, 18), 0, 0),
             (datetime(2022, 9, 19), 322, 4),
             (datetime(2022, 9, 20), 0, 0)]
        )

    # serializer

    def test_serializer_missing_fields(self):
        s = SnowflakeStoreSerializer(data={})
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"account": ["This field is required."],
             "user": ["This field is required."],
             "password": ["This field is required."],
             "database": ["This field is required."],
             "role": ["This field is required."],
             "warehouse": ["This field is required."]}
        )

    def test_serializer_invalid_fields(self):
        s = SnowflakeStoreSerializer(data={
            "account": "",
            "user": "",
            "password": "",
            "database": "",
            "schema": "",
            "role": "",
            "warehouse": "",
            "session_timeout": "30",
        })
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"account": ["This field may not be blank."],
             "user": ["This field may not be blank."],
             "password": ["This field may not be blank."],
             "database": ["This field may not be blank."],
             "schema": ["This field may not be blank."],
             "role": ["This field may not be blank."],
             "warehouse": ["This field may not be blank."],
             "session_timeout": ["Ensure this value is greater than or equal to 60."]}
        )

    def test_serializer_defaults(self):
        s = SnowflakeStoreSerializer(data={
            "account": "account",
            "user": "user",
            "password": "password",
            "database": "database",
            "role": "role",
            "warehouse": "warehouse",
        })
        self.assertTrue(s.is_valid())
        self.assertEqual(
            s.data,
            {"account": "account",
             "user": "user",
             "password": "password",
             "database": "database",
             "schema": "PUBLIC",
             "role": "role",
             "warehouse": "warehouse",
             "session_timeout": 13800}
        )

    def test_serializer_full(self):
        s = SnowflakeStoreSerializer(data={
            "account": "account",
            "user": "user",
            "password": "password",
            "database": "database",
            "schema": "schema",
            "role": "role",
            "warehouse": "warehouse",
            "session_timeout": 123
        })
        self.assertTrue(s.is_valid())
        self.assertEqual(
            s.data,
            {"account": "account",
             "user": "user",
             "password": "password",
             "database": "database",
             "schema": "schema",
             "role": "role",
             "warehouse": "warehouse",
             "session_timeout": 123}
        )

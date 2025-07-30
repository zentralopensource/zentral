from datetime import datetime
from unittest.mock import Mock, patch
from django.test import TestCase
from django.utils.crypto import get_random_string
from accounts.models import Group
from zentral.core.probes.models import ProbeSource
from zentral.core.probes.probe import Probe
from zentral.core.stores.backends.all import StoreBackend
from zentral.core.stores.backends.clickhouse import ClickHouseStore, ClickHouseStoreSerializer
from .utils import build_login_event, force_store


class ClickHouseStoreTestCase(TestCase):
    maxDiff = None

    def get_store(self, **kwargs):
        for arg, default in (("host", "clickhouse"),
                             ("port", 8443),
                             ("secure", True),
                             ("verify", True),
                             ("compress", True),
                             ("username", "username"),
                             ("database", "database"),
                             ("password", "password"),
                             ("access_token", None),
                             ("connect_timeout", 10),
                             ("send_receive_timeout", 300),
                             ("table_engine", "MergeTree"),
                             ("table_name", "zentral_events"),
                             ("ttl_days", 90),
                             ("batch_size", 100)):
            if arg not in kwargs:
                kwargs[arg] = default
        return force_store(backend=StoreBackend.ClickHouse, backend_kwargs=kwargs)

    # backend model

    def test_backend_get_backend(self):
        store = self.get_store()
        self.assertIsInstance(store, ClickHouseStore)
        store2 = store.instance.get_backend(load=True)
        self.assertIsInstance(store2, ClickHouseStore)
        self.assertEqual(store2.instance, store.instance)

    def test_backend_editing(self):
        store = self.get_store()
        self.assertIsNone(store.instance.provisioning_uid)
        self.assertTrue(store.instance.can_be_deleted())
        self.assertTrue(store.instance.can_be_updated())

    def test_provisioned_backend_editing(self):
        store = self.get_store()
        store.instance.provisioning_uid = get_random_string(12)
        store.instance.save()
        self.assertFalse(store.instance.can_be_deleted())
        self.assertFalse(store.instance.can_be_updated())

    def test_backend_encrypted_access_token(self):
        store = self.get_store(access_token="access_token", password="")
        self.assertEqual(
            store.instance.backend_kwargs,
            {'access_token': 'noop$YWNjZXNzX3Rva2Vu',
             'batch_size': 100,
             'compress': True,
             'connect_timeout': 10,
             'database': 'database',
             'host': 'clickhouse',
             'password': 'noop$',
             'port': 8443,
             'secure': True,
             'send_receive_timeout': 300,
             'table_engine': 'MergeTree',
             'table_name': 'zentral_events',
             'ttl_days': 90,
             'username': 'username',
             'verify': True}
        )

    def test_backend_encrypted_password(self):
        store = self.get_store()
        self.assertEqual(
            store.instance.backend_kwargs,
            {'access_token': None,
             'batch_size': 100,
             'compress': True,
             'connect_timeout': 10,
             'database': 'database',
             'host': 'clickhouse',
             'password': 'noop$cGFzc3dvcmQ=',
             'port': 8443,
             'secure': True,
             'send_receive_timeout': 300,
             'table_engine': 'MergeTree',
             'table_name': 'zentral_events',
             'ttl_days': 90,
             'username': 'username',
             'verify': True}
        )

    def test_backend_serialize_for_event_access_token(self):
        store = self.get_store(access_token="access_token", password="")
        store.instance.provisioning_uid = get_random_string(12)
        store.instance.save()
        role = Group.objects.create(name=get_random_string(12))
        store.instance.events_url_authorized_roles.add(role)
        self.assertEqual(
            store.instance.serialize_for_event(),
            {'admin_console': False,
             'backend': 'CLICKHOUSE',
             'backend_kwargs': {
                 'access_token_hash': '86b3901eea37a04e8547cd912225f548d2e0a92078887682ce831a433072f9d1',
                 'batch_size': 100,
                 'compress': True,
                 'connect_timeout': 10,
                 'database': 'database',
                 'host': 'clickhouse',
                 'password_hash': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',  # empty!
                 'port': 8443,
                 'secure': True,
                 'send_receive_timeout': 300,
                 'table_engine': 'MergeTree',
                 'table_name': 'zentral_events',
                 'ttl_days': 90,
                 'username': 'username',
                 'verify': True,
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

    def test_backend_serialize_for_event_password(self):
        store = self.get_store()
        store.instance.provisioning_uid = get_random_string(12)
        store.instance.save()
        role = Group.objects.create(name=get_random_string(12))
        store.instance.events_url_authorized_roles.add(role)
        self.assertEqual(
            store.instance.serialize_for_event(),
            {'admin_console': False,
             'backend': 'CLICKHOUSE',
             'backend_kwargs': {
                 'access_token_hash': None,
                 'batch_size': 100,
                 'compress': True,
                 'connect_timeout': 10,
                 'database': 'database',
                 'host': 'clickhouse',
                 'password_hash': '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
                 'port': 8443,
                 'secure': True,
                 'send_receive_timeout': 300,
                 'table_engine': 'MergeTree',
                 'table_name': 'zentral_events',
                 'ttl_days': 90,
                 'username': 'username',
                 'verify': True,
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

    # event serialization

    def test_event_serialization_min(self):
        username = get_random_string(12)
        event = build_login_event(username)
        dt = datetime(1982, 5, 26)
        event.payload["dt"] = dt
        self.assertEqual(
            self.get_store()._serialize_event(event),
            ((str(event.metadata.uuid), 0),
             (event.metadata.created_at.isoformat(),
              'zentral_login',
              ['zentral'],
              [],
              '',
              {'id': str(event.metadata.uuid),
               'index': 0,
               'namespace': 'zentral'},
              f'{{"user": {{"username": "{username}"}}, '
              '"dt": {"__type__": "datetime", "__value__": "1982-05-26T00:00:00"}}'))
        )

    def test_event_serialization_max(self):
        username = get_random_string(12)
        event = build_login_event(username)
        probe_source = ProbeSource.objects.create(
            name=get_random_string(12),
            status=ProbeSource.ACTIVE,
            body={"filters": {"metadata": [{"event_types": ["zentral_login"]}]}}
        )
        probe = Probe(probe_source)
        event.metadata.add_probe(probe)
        event.metadata.machine_serial_number = "0123456789"
        event.metadata.add_objects({"fomo": [["a"]], "yolo": [["un", "deux"], ["trois", "quatre"]]})
        self.assertEqual(
            self.get_store()._serialize_event(event),
            ((str(event.metadata.uuid), 0),
             (event.metadata.created_at.isoformat(),
              'zentral_login',
              ['zentral'],
              ['_s:0123456789', '_o:fomo:a', '_o:yolo:un|deux', '_o:yolo:trois|quatre', f'_p:{probe.pk}'],
              '0123456789',
              {'id': str(event.metadata.uuid),
               'index': 0,
               'machine_serial_number': '0123456789',
               'namespace': 'zentral',
               'objects': {'fomo': ['a'], 'yolo': ['un|deux', 'trois|quatre']},
               'probes': [{'name': probe.name, 'pk': probe.pk}]},
              f'{{"user": {{"username": "{username}"}}}}'))
        )

    def test_dict_event_serialization(self):
        username = get_random_string(12)
        event = build_login_event(username)
        self.assertEqual(
            self.get_store()._serialize_event(event.serialize()),
            ((str(event.metadata.uuid), 0),
             (event.metadata.created_at.isoformat(),
              'zentral_login',
              ['zentral'],
              [],
              '',
              {'id': str(event.metadata.uuid),
               'index': 0,
               'namespace': 'zentral'},
              f'{{"user": {{"username": "{username}"}}}}'))
        )

    # event storage

    @patch("zentral.core.stores.backends.clickhouse.clickhouse_connect.get_client")
    def test_store(self, get_client):
        mocked_client = Mock()
        get_client.return_value = mocked_client
        store = self.get_store()
        event = build_login_event()
        store.store(event)
        mocked_client.command.assert_called_once()
        mocked_client.insert.assert_called_once()

    @patch("zentral.core.stores.backends.clickhouse.clickhouse_connect.get_client")
    def test_bulk_store(self, get_client):
        mocked_client = Mock()
        get_client.return_value = mocked_client
        store = self.get_store()
        event = build_login_event()
        event_keys = store.bulk_store([event])
        self.assertEqual(event_keys, [(str(event.metadata.uuid), 0)])
        mocked_client.command.assert_called_once()
        mocked_client.insert.assert_called_once()

    # serializer

    def test_serializer_missing_fields(self):
        s = ClickHouseStoreSerializer(data={})
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"host": ["This field is required."]}
        )

    def test_serializer_invalid_fields(self):
        s = ClickHouseStoreSerializer(data={
            "host": "",
            "port": 123456789,
            "database": "1 2 3 4",
            "connect_timeout": -1,
            "send_receive_timeout": -1,
            "table_engine": "1 2 3 4",
            "ttl_days": -1,
            "batch_size": 123456789,
        })
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"host": ["This field may not be blank."],
             "port": ["Ensure this value is less than or equal to 65535."],
             "database": ["This value does not match the required pattern."],
             "connect_timeout": ["Ensure this value is greater than or equal to 1."],
             "send_receive_timeout": ["Ensure this value is greater than or equal to 1."],
             "table_engine": ["This value does not match the required pattern."],
             "ttl_days": ["Ensure this value is greater than or equal to 1."],
             "batch_size": ["Ensure this value is less than or equal to 1000."]}
        )

    def test_serializer_auth_conflict_username(self):
        s = ClickHouseStoreSerializer(data={
            "host": "clickhouse",
            "username": "yolo",
            "access_token": "access_token",
        })
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"non_field_errors": ["Cannot use both access_token and username/password"]},
        )

    def test_serializer_auth_conflict_password(self):
        s = ClickHouseStoreSerializer(data={
            "host": "clickhouse",
            "password": "yolo",
            "access_token": "access_token",
        })
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"non_field_errors": ["Cannot use both access_token and username/password"]},
        )

    def test_serializer_defaults(self):
        s = ClickHouseStoreSerializer(data={"host": "clickhouse"})
        self.assertTrue(s.is_valid())
        self.assertEqual(
            s.data,
            {'host': 'clickhouse',
             'port': 8443,
             'secure': True,
             'verify': True,
             'compress': True,
             'username': None,
             'database': 'default',
             'password': '',
             'access_token': None,
             'connect_timeout': 10,
             'send_receive_timeout': 300,
             'table_engine': 'MergeTree',
             'table_name': 'zentral_events',
             'ttl_days': 90,
             'batch_size': 100}
        )

    def test_serializer_full(self):
        data = {
            'host': 'clickhouse',
            'port': 8123,
            'secure': False,
            'verify': False,
            'compress': False,
            'username': "username",
            'database': 'default',
            'password': "password",
            'access_token': None,
            'connect_timeout': 12,
            'send_receive_timeout': 345,
            'table_engine': 'ReplicatedMergeTree',
            'table_name': 'table_name',
            'ttl_days': 678,
            'batch_size': 910
        }
        s = ClickHouseStoreSerializer(data=data)
        self.assertTrue(s.is_valid())
        self.assertEqual(s.data, data)

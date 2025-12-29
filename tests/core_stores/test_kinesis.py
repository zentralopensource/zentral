import json
import uuid
from unittest.mock import patch, Mock
from django.test import TestCase
from django.utils.crypto import get_random_string
from accounts.events import EventMetadata, EventRequest, LoginEvent
from accounts.models import Group
from zentral.core.stores.backends.all import StoreBackend
from zentral.core.stores.backends.kinesis import KinesisStore, KinesisStoreSerializer
from .utils import build_login_event, force_store


class KinesisStoreTestCase(TestCase):
    maxDiff = None

    def get_store(self, **kwargs):
        for arg, default in (
            ("stream", "123"),
            ("region_name", "us-east-1"),
            ("aws_access_key_id", "yolo"),
            ("aws_secret_access_key", "fomo"),
            ("assume_role_arn", "arn::role"),
            ("batch_size", 17),
            ("serialization_format", "firehose_v1")
        ):
            if arg not in kwargs:
                kwargs[arg] = default
        return force_store(backend=StoreBackend.Kinesis, backend_kwargs=kwargs)

    # backend model

    def test_backend_get_backend(self):
        store = self.get_store()
        self.assertIsInstance(store, KinesisStore)
        store2 = store.instance.get_backend(load=True)
        self.assertIsInstance(store2, KinesisStore)
        self.assertEqual(store2.instance, store.instance)

    def test_backend_encrypted_kwargs(self):
        store = self.get_store()
        self.assertEqual(
            store.instance.backend_kwargs,
            {'stream': '123',
             'region_name': 'us-east-1',
             'aws_access_key_id': 'yolo',
             'aws_secret_access_key': 'noop$Zm9tbw==',  # "encrypted"
             'assume_role_arn': 'arn::role',
             'batch_size': 17,
             'serialization_format': 'firehose_v1'},
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
             'backend': 'KINESIS',
             'backend_kwargs': {
                 'stream': '123',
                 'region_name': 'us-east-1',
                 'aws_access_key_id': 'yolo',
                 'aws_secret_access_key_hash': '48ffcddb8b19a5f98d4b1b8c08b4024b12b6f24affeb50b1265aed528a2dd671',
                 'assume_role_arn': 'arn::role',
                 'batch_size': 17,
                 'serialization_format': 'firehose_v1'
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

    @patch("zentral.core.stores.backends.kinesis.make_refreshable_assume_role_session")
    def test_assume_role(self, mrars):
        def noop_mrars(session, option):
            return session
        mrars.side_effect = noop_mrars
        store = self.get_store(aws_access_key_id="123", aws_secret_access_key="456", assume_role_arn="yolo")
        self.assertFalse(store.configured)
        store.wait_and_configure()
        self.assertTrue(store.configured)
        mrars.assert_called_once()

    # event serialization

    def test_firehose_v1_serialization(self):
        m_uuid = uuid.uuid4()
        m_index = 3
        metadata = EventMetadata(
            uuid=m_uuid,
            index=m_index,
            objects={"osquery_enrollment": [(19,)]},
            probes=[{"pk": 18, "name": get_random_string(12)}],
            request=EventRequest(user_agent="user_agent", ip="203.0.113.10"),
            tags=["yolo", "fomo"]
        )
        username = get_random_string(12)
        event = LoginEvent(metadata, {"user": {"username": username}})
        store = self.get_store(serialization_format="firehose_v1")
        serialized_event, partition_key, event_id, event_index = store._serialize_event(event)
        self.assertEqual(event_id, str(m_uuid))
        self.assertEqual(event_index, m_index)
        self.assertEqual(partition_key, f"{m_uuid}{m_index}")
        serialized_event_d = json.loads(serialized_event.decode("utf-8"))
        self.assertEqual(serialized_event_d["type"], event.metadata.event_type)
        self.assertEqual(serialized_event_d["created_at"], event.metadata.created_at.isoformat())
        self.assertEqual(serialized_event_d["serial_number"], None)
        self.assertEqual(json.loads(serialized_event_d["payload"]), {"user": {"username": username}})
        self.assertEqual(serialized_event_d["objects"], ["osquery_enrollment:19"])
        self.assertEqual(sorted(serialized_event_d["tags"]), ["fomo", "yolo", "zentral"])
        self.assertEqual(serialized_event_d["probes"], [18])
        loaded_metadata = json.loads(serialized_event_d["metadata"])
        self.assertEqual(loaded_metadata["id"], str(m_uuid))
        self.assertEqual(loaded_metadata["index"], m_index)
        self.assertNotIn("objects", loaded_metadata)
        self.assertNotIn("tags", loaded_metadata)
        self.assertNotIn("type", loaded_metadata)

    def test_store_zentral_format(self):
        store = self.get_store()
        store.configured = True
        mock_client = Mock()
        mock_client.put_record.return_value = "TEST RETURN VALUE"
        store.client = mock_client
        event = build_login_event()
        self.assertEqual(store.store(event), "TEST RETURN VALUE")
        mock_client.put_record.assert_called_once()

    def test_store_firehose_v1_format(self):
        store = self.get_store(serialization_format="firehose_v1")
        store.configured = True
        mock_client = Mock()
        mock_client.put_record.return_value = "TEST RETURN VALUE"
        store.client = mock_client
        event = build_login_event()
        self.assertEqual(store.store(event), "TEST RETURN VALUE")
        mock_client.put_record.assert_called_once()

    # event storage

    def test_bulk_store_not_available(self):
        store = self.get_store(serialization_format="firehose_v1", batch_size=1)
        store.configured = True
        event = build_login_event()
        with self.assertRaises(RuntimeError) as cm:
            list(store.bulk_store([event]))
        self.assertEqual(cm.exception.args[0], "bulk_store is not available when batch_size < 2")

    def test_bulk_store_noop(self):
        store = self.get_store(batch_size=50, serialization_format="firehose_v1")
        store.configured = True
        self.assertEqual(list(store.bulk_store([])), [])

    def test_bulk_store_zentral_format_all_ok(self):
        store = self.get_store(batch_size=50, serialization_format="firehose_v1")
        store.configured = True
        mock_client = Mock()
        mock_client.put_records.return_value = {"FailedRecordCount": 0}
        store.client = mock_client
        event = build_login_event()
        self.assertEqual(
            list(store.bulk_store([event])),
            [(str(event.metadata.uuid), event.metadata.index)]
        )

    def test_bulk_store_zentral_format_partially_ok(self):
        store = self.get_store(batch_size=50, serialization_format="firehose_v1")
        store.configured = True
        mock_client = Mock()
        mock_client.put_records.return_value = {
            "FailedRecordCount": 1,
            "Records": [
                {}, {"SequenceNumber": 1, "ShardId": 2}
            ]
        }
        store.client = mock_client
        event1 = build_login_event()
        event2 = build_login_event()
        self.assertEqual(
            list(store.bulk_store([event1, event2])),
            [(str(event2.metadata.uuid), event2.metadata.index)]
        )

    # serializer

    def test_serializer_missing_fields(self):
        s = KinesisStoreSerializer(data={})
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"stream": ["This field is required."],
             "region_name": ["This field is required."],
             "serialization_format": ["This field is required."]}
        )

    def test_serializer_invalid_fields(self):
        s = KinesisStoreSerializer(data={
            "stream": "",
            "region_name": "",
            "batch_size": 1234,
            "serialization_format": "yolo",
        })
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"stream": ["This field may not be blank."],
             "region_name": ["This field may not be blank."],
             "batch_size": ["Ensure this value is less than or equal to 500."],
             "serialization_format": ['"yolo" is not a valid choice.']}
        )

    def test_serializer_defaults(self):
        s = KinesisStoreSerializer(data={
            "stream": "123",
            "region_name": "us-central-1",
            "serialization_format": "zentral",
        })
        self.assertTrue(s.is_valid())
        self.assertEqual(
            s.data,
            {"stream": "123",
             "aws_access_key_id": None,
             "aws_secret_access_key": None,
             "assume_role_arn": None,
             "region_name": "us-central-1",
             "batch_size": 1,
             "serialization_format": "zentral"},
        )

    def test_serializer_key_full(self):
        s = KinesisStoreSerializer(data={
            "stream": "123",
            "region_name": "us-central-1",
            "aws_access_key_id": "yolo",
            "aws_secret_access_key": "fomo",
            "batch_size": 42,
            "serialization_format": "firehose_v1",
        })
        self.assertTrue(s.is_valid())
        self.assertEqual(
            s.data,
            {"stream": "123",
             "region_name": "us-central-1",
             "aws_access_key_id": "yolo",
             "aws_secret_access_key": "fomo",
             "assume_role_arn": None,
             "batch_size": 42,
             "serialization_format": "firehose_v1"},
        )

    def test_serializer_role_full(self):
        s = KinesisStoreSerializer(data={
            "stream": "123",
            "region_name": "us-central-1",
            "assume_role_arn": "arn::role",
            "batch_size": 42,
            "serialization_format": "firehose_v1",
        })
        self.assertTrue(s.is_valid())
        self.assertEqual(
            s.data,
            {"stream": "123",
             "region_name": "us-central-1",
             "aws_access_key_id": None,
             "aws_secret_access_key": None,
             "assume_role_arn": "arn::role",
             "batch_size": 42,
             "serialization_format": "firehose_v1"},
        )

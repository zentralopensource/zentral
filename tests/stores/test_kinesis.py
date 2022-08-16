import json
import uuid
from unittest.mock import patch, Mock
from django.test import SimpleTestCase
from django.utils.crypto import get_random_string
from accounts.events import EventMetadata, EventRequest, LoginEvent
from zentral.core.exceptions import ImproperlyConfigured
from zentral.core.stores.backends.kinesis import EventStore


class KinesisStoreTestCase(SimpleTestCase):
    def get_store(self, **kwargs):
        for arg, default in (("store_name", get_random_string(12)),
                             ("batch_size", None),
                             ("stream", "123"),
                             ("region_name", "us-east-1"),
                             ("aws_access_key_id", None),
                             ("aws_secret_access_key", None),
                             ("assume_role_arn", None),
                             ("serialization_format", None)):
            val = kwargs.get(arg)
            if val is None and default is not None:
                kwargs[arg] = default
        return EventStore(kwargs)

    def build_login_event(self, username=None):
        if username is None:
            username = get_random_string(12)
        return LoginEvent(EventMetadata(), {"user": {"username": username}})

    def test_default_store(self):
        store = self.get_store()
        self.assertEqual(store.credentials, {})
        self.assertIsNone(store.assume_role_arn)
        self.assertEqual(store.serialization_format, "zentral")

    def test_store_options(self):
        store = self.get_store(
                aws_access_key_id="123", aws_secret_access_key="456",
                assume_role_arn="yolo", serialization_format="firehose_v1"
        )
        self.assertEqual(store.credentials, {"aws_access_key_id": "123", "aws_secret_access_key": "456"})
        self.assertEqual(store.assume_role_arn, "yolo")
        self.assertEqual(store.serialization_format, "firehose_v1")

    def test_unknown_serialization_format(self):
        with self.assertRaises(ImproperlyConfigured) as cm:
            self.get_store(serialization_format="yolo")
        self.assertEqual(cm.exception.args[0], "Unknown serialization format")

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

    def test_firehose_v1_serialization(self):
        m_uuid = uuid.uuid4()
        m_index = 3
        metadata = EventMetadata(
            uuid=m_uuid,
            index=m_index,
            objects={"osquery_enrollment": [(19,)]},
            probes=[{"pk": 18, "name": get_random_string()}],
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
        event = self.build_login_event()
        self.assertEqual(store.store(event), "TEST RETURN VALUE")
        mock_client.put_record.assert_called_once()

    def test_store_firehose_v1_format(self):
        store = self.get_store(serialization_format="firehose_v1")
        store.configured = True
        mock_client = Mock()
        mock_client.put_record.return_value = "TEST RETURN VALUE"
        store.client = mock_client
        event = self.build_login_event()
        self.assertEqual(store.store(event), "TEST RETURN VALUE")
        mock_client.put_record.assert_called_once()

    def test_bulk_store_not_available(self):
        store = self.get_store(serialization_format="firehose_v1")
        store.configured = True
        event = self.build_login_event()
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
        event = self.build_login_event()
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
        event1 = self.build_login_event()
        event2 = self.build_login_event()
        self.assertEqual(
            list(store.bulk_store([event1, event2])),
            [(str(event2.metadata.uuid), event2.metadata.index)]
        )

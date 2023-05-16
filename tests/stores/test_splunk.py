from unittest.mock import patch, Mock
import uuid
from django.test import SimpleTestCase
from django.utils.crypto import get_random_string
from accounts.events import EventMetadata, LoginEvent
from zentral.core.stores.backends.splunk import EventStore


class TestSplunkStore(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.store = EventStore({"store_name": get_random_string(12),
                                "hec_url": "https://splunk.example.com:8088",
                                "hec_token": get_random_string(12),
                                "batch_size": 2})

    @staticmethod
    def build_login_event():
        return LoginEvent(EventMetadata(), {"user": {"username": get_random_string(12)}})

    def test_event_id_serialization(self):
        event = self.build_login_event()
        serialized_event = self.store._serialize_event(event)
        self.assertEqual(serialized_event["event"]["id"], f"{str(event.metadata.uuid)}:{event.metadata.index}")
        self.assertNotIn("index", serialized_event["event"])

    def test_serialized_event_id_serialization(self):
        event = self.build_login_event()
        serialized_event = self.store._serialize_event(event.serialize())
        self.assertEqual(serialized_event["event"]["id"], f"{str(event.metadata.uuid)}:{event.metadata.index}")
        self.assertNotIn("index", serialized_event["event"])

    def test_event_id_deserialization(self):
        serialized_event = {
            "_raw": '{"id": "f83b54ef-d3de-42c9-ae61-76669dcac0a9:17", '
                    '"namespace": "zentral", "tags": ["zentral"], '
                    '"zentral": {"user": {"username": "YONpsAgaKguu"}}}',
            "_time": "2010-07-18T19:19:30.000+00:00",
            "sourcetype": "zentral_login",
        }
        event = self.store._deserialize_event(serialized_event)
        self.assertEqual(event.event_type, "zentral_login")
        self.assertEqual(event.metadata.uuid, uuid.UUID("f83b54ef-d3de-42c9-ae61-76669dcac0a9"))
        self.assertEqual(event.metadata.index, 17)
        self.assertEqual(event.metadata.namespace, "zentral")
        self.assertEqual(event.payload["user"], {"username": "YONpsAgaKguu"})

    def test_legacy_event_id_deserialization(self):
        serialized_event = {
            "_raw": '{"id": "f83b54ef-d3de-42c9-ae61-76669dcac0a9", "index": 42,'
                    '"namespace": "zentral", "tags": ["zentral"], '
                    '"zentral": {"user": {"username": "YONpsAgaKguu"}}}',
            "_time": "2010-07-18T19:19:30.000+00:00",
            "sourcetype": "zentral_login",
        }
        event = self.store._deserialize_event(serialized_event)
        self.assertEqual(event.event_type, "zentral_login")
        self.assertEqual(event.metadata.uuid, uuid.UUID("f83b54ef-d3de-42c9-ae61-76669dcac0a9"))
        self.assertEqual(event.metadata.index, 42)
        self.assertEqual(event.metadata.namespace, "zentral")
        self.assertEqual(event.payload["user"], {"username": "YONpsAgaKguu"})

    def test_custom_host_field_serialization(self):
        event = self.build_login_event()
        self.store.custom_host_field = "computername"
        serialized_event = self.store._serialize_event(event)
        self.assertEqual(serialized_event["event"]["computername"], "Zentral")
        self.store.custom_host_field = None

    def test_custom_host_field_deserialization(self):
        serialized_event = {
            "_raw": '{"id": "f83b54ef-d3de-42c9-ae61-76669dcac0a9:17", '
                    '"namespace": "zentral", "tags": ["zentral"], '
                    '"computername": "Zentral", '
                    '"zentral": {"user": {"username": "YONpsAgaKguu"}}}',
            "_time": "2010-07-18T19:19:30.000+00:00",
            "sourcetype": "zentral_login",
        }
        self.store.custom_host_field = "computername"
        event = self.store._deserialize_event(serialized_event)
        self.assertEqual(event.metadata.uuid, uuid.UUID("f83b54ef-d3de-42c9-ae61-76669dcac0a9"))
        self.store.custom_host_field = None

    @patch("zentral.core.stores.backends.splunk.EventStore.hec_session")
    @patch("zentral.core.stores.backends.splunk.time.sleep")
    def test_store_event_error_retry(self, sleep, hec_session):
        response = Mock()
        response.ok = False
        response.status_code = 501
        response.raise_for_status.side_effect = Exception("BOOM!")
        hec_session.post.return_value = response
        event = self.build_login_event()
        with self.assertRaises(Exception) as cm:
            self.store.store(event)
        self.assertEqual(cm.exception.args[0], "BOOM!")
        self.assertEqual(len(hec_session.post.call_args_list), 3)
        self.assertEqual(len(sleep.call_args_list), 2)

    @patch("zentral.core.stores.backends.splunk.EventStore.hec_session")
    @patch("zentral.core.stores.backends.splunk.time.sleep")
    def test_store_event_error_no_retry(self, sleep, hec_session):
        response = Mock()
        response.ok = False
        response.status_code = 500
        response.raise_for_status.side_effect = Exception("BOOM!")
        hec_session.post.return_value = response
        event = self.build_login_event()
        with self.assertRaises(Exception) as cm:
            self.store.store(event)
        self.assertEqual(cm.exception.args[0], "BOOM!")
        self.assertEqual(len(hec_session.post.call_args_list), 1)
        self.assertEqual(len(sleep.call_args_list), 0)

    @patch("zentral.core.stores.backends.splunk.EventStore.hec_session")
    @patch("zentral.core.stores.backends.splunk.time.sleep")
    def test_bulk_store_events_error_retry(self, sleep, hec_session):
        response = Mock()
        response.ok = False
        response.status_code = 501
        response.raise_for_status.side_effect = Exception("BOOM!")
        hec_session.post.return_value = response
        events = [self.build_login_event(), self.build_login_event()]
        with self.assertRaises(Exception) as cm:
            self.store.bulk_store(events)
        self.assertEqual(cm.exception.args[0], "BOOM!")
        self.assertEqual(len(hec_session.post.call_args_list), 3)
        self.assertEqual(len(sleep.call_args_list), 2)

    @patch("zentral.core.stores.backends.splunk.EventStore.hec_session")
    @patch("zentral.core.stores.backends.splunk.time.sleep")
    def test_bulk_store_events_error_no_retry(self, sleep, hec_session):
        response = Mock()
        response.ok = False
        response.status_code = 400
        response.raise_for_status.side_effect = Exception("BOOM!")
        hec_session.post.return_value = response
        events = [self.build_login_event(), self.build_login_event()]
        with self.assertRaises(Exception) as cm:
            self.store.bulk_store(events)
        self.assertEqual(cm.exception.args[0], "BOOM!")
        self.assertEqual(len(hec_session.post.call_args_list), 1)
        self.assertEqual(len(sleep.call_args_list), 0)

import uuid
from django.test import SimpleTestCase
from django.utils.crypto import get_random_string
from accounts.events import EventMetadata, LoginEvent
from zentral.core.stores.backends.splunk import EventStore


class TestSplunkStore(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.store = EventStore({"store_name": get_random_string(),
                                "hec_url": "https://splunk.example.com:8088",
                                "hec_token": get_random_string()})

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

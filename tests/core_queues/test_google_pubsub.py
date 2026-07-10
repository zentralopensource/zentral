from unittest.mock import Mock, patch
from django.test import TestCase
from zentral.core.queues.backends.google_pubsub import EventQueues


class GooglePubSubQueuesTestCase(TestCase):
    maxDiff = None

    @staticmethod
    def get_queues():
        return EventQueues({
            "topics": {
                "raw_events": "projects/p/topics/raw-events",
                "events": "projects/p/topics/events",
                "enriched_events": "projects/p/topics/enriched-events",
            }
        })

    def test_create_event_queues(self):
        eq = self.get_queues()
        self.assertEqual(eq.raw_events_topic, "projects/p/topics/raw-events")
        self.assertEqual(eq.events_topic, "projects/p/topics/events")
        self.assertEqual(eq.enriched_events_topic, "projects/p/topics/enriched-events")
        self.assertIsNone(eq.credentials)
        self.assertIsNone(eq.publisher_client)

    @patch("zentral.core.queues.backends.google_pubsub.pubsub_v1.PublisherClient")
    def test_publish_creates_publisher_client_once(self, PublisherClient):
        eq = self.get_queues()
        event = Mock()
        event.event_type = "yolo"
        event.serialize.return_value = {"_zentral": {"type": "yolo"}}
        eq.post_event(event)
        # concurrent publishes must reuse the single lazily-built PublisherClient
        eq.post_raw_event("routing-key", {"foo": "bar"})
        eq.post_event(event)
        event.serialize.assert_called_with(machine_metadata=False)
        PublisherClient.assert_called_once_with(credentials=None)
        self.assertIs(eq.publisher_client, PublisherClient.return_value)
        publish = PublisherClient.return_value.publish
        self.assertEqual(publish.call_count, 3)
        # topic + attributes per call; the payload is JSON-encoded bytes
        self.assertEqual(
            [c.args[0] for c in publish.call_args_list],
            ["projects/p/topics/events", "projects/p/topics/raw-events", "projects/p/topics/events"]
        )
        self.assertIsInstance(publish.call_args_list[0].args[1], bytes)
        self.assertEqual(publish.call_args_list[0].kwargs, {"event_type": "yolo"})
        self.assertEqual(publish.call_args_list[1].kwargs, {"routing_key": "routing-key"})

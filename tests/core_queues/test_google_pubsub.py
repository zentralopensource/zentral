from unittest.mock import Mock, patch
from django.test import TestCase
from zentral.core.queues.backends.google_pubsub import EventQueues, PreprocessWorker
from zentral.core.queues.backends.google_pubsub.consumer import BaseWorker
from zentral.core.queues.exceptions import RetryLater


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

    def test_preprocess_worker_callback_publishes_events(self):
        w = self.get_queues().get_preprocess_worker()
        self.assertIsInstance(w, PreprocessWorker)
        w.metrics_exporter = None
        w.publish_event = Mock()
        event = Mock(event_type="yolo")
        preprocessor = Mock(routing_key="test_routing_key")
        preprocessor.process_raw_event.return_value = iter([event])
        w.preprocessors = {"test_routing_key": preprocessor}
        message = Mock(data=b'{"foo": "bar"}')
        message.attributes = {"routing_key": "test_routing_key"}
        w.callback(message)
        preprocessor.process_raw_event.assert_called_once_with({"foo": "bar"})
        w.publish_event.assert_called_once_with(event, machine_metadata=False)
        message.ack.assert_called_once()

    def test_preprocess_worker_callback_nacks_on_retry_later(self):
        w = self.get_queues().get_preprocess_worker()
        w.metrics_exporter = None
        w.publish_event = Mock()
        preprocessor = Mock(routing_key="test_routing_key")
        preprocessor.process_raw_event.side_effect = RetryLater
        w.preprocessors = {"test_routing_key": preprocessor}
        message = Mock(data=b'{"foo": "bar"}')
        message.attributes = {"routing_key": "test_routing_key"}
        w.callback(message)
        message.nack.assert_called_once()
        message.ack.assert_not_called()

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


class GooglePubSubBaseWorkerTestCase(TestCase):
    maxDiff = None

    @patch("zentral.core.queues.backends.google_pubsub.consumer.setup_signal_handler")
    def test_run_wires_signal_handler(self, setup_signal_handler):
        worker = BaseWorker("projects/p/topics/events", None)
        worker.ensure_subscription = Mock()
        worker.start_metrics_exporter = Mock()
        worker.do_run = Mock()
        self.assertEqual(worker.run(), 0)
        worker.ensure_subscription.assert_called_once()
        setup_signal_handler.assert_called_once_with(worker.handle_signal)
        worker.start_metrics_exporter.assert_called_once()
        worker.do_run.assert_called_once()

    @patch("zentral.core.queues.backends.google_pubsub.consumer.setup_signal_handler")
    def test_run_skips_signal_handler_when_subscription_fails(self, setup_signal_handler):
        worker = BaseWorker("projects/p/topics/events", None)
        worker.ensure_subscription = Mock(side_effect=ValueError)
        worker.start_metrics_exporter = Mock()
        worker.do_run = Mock()
        self.assertEqual(worker.run(), 1)
        setup_signal_handler.assert_not_called()
        worker.do_run.assert_not_called()

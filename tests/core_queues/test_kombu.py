from unittest.mock import Mock, PropertyMock, patch
from django.test import SimpleTestCase
from zentral.core.queues.backends.kombu import EventQueues, PreprocessWorker
from zentral.core.queues.compression import COMPRESSED_RAW_EVENT_KEY, decompress_raw_event
from zentral.core.queues.exceptions import RetryLater
from .test_compression import build_big_raw_event


class KombuPreprocessWorkerTestCase(SimpleTestCase):
    def test_do_preprocess_raw_event_publishes_events(self):
        w = PreprocessWorker(Mock())
        w.metrics_exporter = None
        event = Mock(event_type="yolo")
        event.serialize.return_value = {"_zentral": {"type": "yolo"}}
        preprocessor = Mock(routing_key="test_routing_key")
        preprocessor.process_raw_event.return_value = iter([event])
        w.preprocessors = {"test_routing_key": preprocessor}
        message = Mock()
        message.delivery_info = {"routing_key": "test_routing_key"}
        with patch.object(PreprocessWorker, "producer", new_callable=PropertyMock) as producer:
            w.do_preprocess_raw_event({"foo": "bar"}, message)
        preprocessor.process_raw_event.assert_called_once_with({"foo": "bar"})
        producer.return_value.publish.assert_called_once()
        message.ack.assert_called_once()

    def test_do_preprocess_raw_event_requeues_on_retry_later(self):
        w = PreprocessWorker(Mock())
        w.metrics_exporter = None
        preprocessor = Mock(routing_key="test_routing_key")
        preprocessor.process_raw_event.side_effect = RetryLater
        w.preprocessors = {"test_routing_key": preprocessor}
        message = Mock()
        message.delivery_info = {"routing_key": "test_routing_key"}
        with patch.object(PreprocessWorker, "producer", new_callable=PropertyMock):
            w.do_preprocess_raw_event({"foo": "bar"}, message)
        message.requeue.assert_called_once()
        message.ack.assert_not_called()


class KombuEventQueuesTestCase(SimpleTestCase):
    maxDiff = None

    @patch("zentral.core.queues.backends.kombu.producers")
    def test_post_raw_event_compresses_big_raw_event(self, producers):
        eq = EventQueues({"backend_url": "memory://"})
        raw_event = build_big_raw_event()
        eq.post_raw_event("routing-key", raw_event)
        publish = producers.__getitem__.return_value.acquire.return_value.__enter__.return_value.publish
        publish.assert_called_once()
        posted_raw_event = publish.call_args.args[0]
        self.assertEqual(list(posted_raw_event), [COMPRESSED_RAW_EVENT_KEY])
        self.assertEqual(decompress_raw_event(posted_raw_event), raw_event)
        self.assertEqual(publish.call_args.kwargs["routing_key"], "routing-key")

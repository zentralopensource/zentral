from unittest.mock import Mock, PropertyMock, patch
from django.test import SimpleTestCase
from zentral.core.queues.backends.kombu import PreprocessWorker
from zentral.core.queues.exceptions import RetryLater


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

from unittest.mock import patch
from django.db import InterfaceError, OperationalError
from django.test import SimpleTestCase
from zentral.core.queues.exceptions import RetryLater
from zentral.core.queues.preprocessing import iter_preprocessed_events

CLOSE_OLD_CONNECTIONS = "zentral.core.queues.preprocessing.close_old_connections"


class _Preprocessor:
    routing_key = "test_routing_key"

    def __init__(self, events=None, error=None):
        self._events = events or []
        self._error = error

    def process_raw_event(self, raw_event):
        yield from self._events
        if self._error is not None:
            raise self._error


class IterPreprocessedEventsTestCase(SimpleTestCase):
    """iter_preprocessed_events is the single entry point every queue backend uses to run a
    preprocessor: it resolves the routing key and recycles a dropped pooled connection."""

    @staticmethod
    def _preprocessors(preprocessor):
        return {preprocessor.routing_key: preprocessor}

    def test_events_pass_through_without_touching_connections(self):
        pp = _Preprocessor(events=["a", "b"])
        with patch(CLOSE_OLD_CONNECTIONS) as close_old_connections:
            self.assertEqual(
                list(iter_preprocessed_events(self._preprocessors(pp), pp.routing_key, {})),
                ["a", "b"],
            )
        close_old_connections.assert_not_called()

    def test_missing_routing_key_yields_nothing(self):
        pp = _Preprocessor(events=["a"])
        with self.assertLogs("zentral.core.queues.preprocessing", level="ERROR") as cm:
            self.assertEqual(list(iter_preprocessed_events(self._preprocessors(pp), None, {})), [])
        self.assertIn("Message without routing key", cm.output[0])

    def test_unknown_routing_key_yields_nothing(self):
        with self.assertLogs("zentral.core.queues.preprocessing", level="ERROR") as cm:
            self.assertEqual(list(iter_preprocessed_events({}, "unknown_routing_key", {})), [])
        self.assertIn("No preprocessor for routing key unknown_routing_key", cm.output[0])

    def test_operational_error_recycles_connection_and_reenqueues(self):
        pp = _Preprocessor(error=OperationalError("server closed the connection unexpectedly"))
        with patch(CLOSE_OLD_CONNECTIONS) as close_old_connections:
            with self.assertRaises(RetryLater):
                list(iter_preprocessed_events(self._preprocessors(pp), pp.routing_key, {}))
        close_old_connections.assert_called_once()

    def test_interface_error_recycles_connection_and_reenqueues(self):
        pp = _Preprocessor(error=InterfaceError("connection already closed"))
        with patch(CLOSE_OLD_CONNECTIONS) as close_old_connections:
            with self.assertRaises(RetryLater):
                list(iter_preprocessed_events(self._preprocessors(pp), pp.routing_key, {}))
        close_old_connections.assert_called_once()

    def test_retry_later_passes_through_without_recycling(self):
        pp = _Preprocessor(error=RetryLater())
        with patch(CLOSE_OLD_CONNECTIONS) as close_old_connections:
            with self.assertRaises(RetryLater):
                list(iter_preprocessed_events(self._preprocessors(pp), pp.routing_key, {}))
        close_old_connections.assert_not_called()

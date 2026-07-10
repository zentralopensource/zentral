from unittest.mock import patch
from django.test import SimpleTestCase


class EventQueueShutdownHooksTestCase(SimpleTestCase):
    @patch("zentral.core.queues.queues.stop")
    def test_gunicorn_worker_exit_stops_queues(self, stop):
        from server.gunicorn_conf import worker_exit
        worker_exit(None, None)
        stop.assert_called_once_with()

    @patch("zentral.core.queues.queues.stop")
    def test_celery_worker_shutdown_stops_queues(self, stop):
        from server.celery import stop_event_queues
        stop_event_queues()
        stop.assert_called_once_with()

import logging
import queue
import signal
import threading
import time
from .sqs import SQSDeleteThread, SQSReceiveThread


logger = logging.getLogger("zentral.core.queues.backends.aws_sns_sqs.consumer")


class Consumer:
    def __init__(self, queue_url, client_kwargs=None):
        if client_kwargs is None:
            client_kwargs = {}
        self.process_message_queue = queue.Queue(maxsize=15)
        self.delete_message_queue = queue.Queue(maxsize=15)
        self.stop_event = threading.Event()
        self._threads = [
            SQSDeleteThread(queue_url, self.stop_event, self.delete_message_queue, client_kwargs),
            SQSReceiveThread(queue_url, self.stop_event, self.process_message_queue, client_kwargs)
        ]

    def _gracefull_stop(self, signum, frame):
        if signum == signal.SIGTERM:
            signum = "SIGTERM"
        elif signum == signal.SIGINT:
            signum = "SIGINT"
        logger.debug("Received signal %s", signum)
        if not self.stop_event.is_set():
            logger.error("Signal %s. Initiate gracefull stop.", signum)
            self.stop_event.set()
            for thread in self._threads:
                thread.join()
            logger.error("All threads stopped.")

    def process_event(self, routing_key, event_d):
        pass

    def run(self, *args, **kwargs):
        self.log_info("run")
        signal.signal(signal.SIGTERM, self._gracefull_stop)
        signal.signal(signal.SIGINT, self._gracefull_stop)
        for thread in self._threads:
            thread.start()
        while True:
            try:
                receipt_handle, routing_key, event_d = self.process_message_queue.get(block=True, timeout=1)
            except queue.Empty:
                if self.stop_event.is_set():
                    break
            else:
                try:
                    self.process_event(routing_key, event_d)
                except Exception:
                    logger.exception("Could not process event")
                else:
                    logger.debug("Queue message for deletion %s", receipt_handle)
                    self.delete_message_queue.put((receipt_handle, time.time()))


class ConsumerProducer(Consumer):
    def __init__(self, queue_url, client_kwargs=None):
        super().__init__(queue_url, client_kwargs)
        self.publish_message_queue = queue.Queue(maxsize=20)

    def generate_events(self, routing_key, event_d):
        return []

    def process_event(self, routing_key, event_d):
        for new_routing_key, new_event_d in self.generate_events(routing_key, event_d):
            self.publish_message_queue.put((new_routing_key, new_event_d, time.time()))
